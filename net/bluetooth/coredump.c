// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2023 Google Corporation
 */

#include <linux/devcoredump.h>

#include <asm/unaligned.h>
#include <net/bluetooth/bluetooth.h>
#include <net/bluetooth/hci_core.h>

enum hci_devcoredump_pkt_type {
	HCI_DEVCOREDUMP_PKT_INIT,
	HCI_DEVCOREDUMP_PKT_SKB,
	HCI_DEVCOREDUMP_PKT_PATTERN,
	HCI_DEVCOREDUMP_PKT_COMPLETE,
	HCI_DEVCOREDUMP_PKT_ABORT,
};

struct hci_devcoredump_skb_cb {
	u16 pkt_type;
};

struct hci_devcoredump_skb_pattern {
	u8 pattern;
	u32 len;
} __packed;

#define hci_dmp_cb(skb)	((struct hci_devcoredump_skb_cb *)((skb)->cb))

#define DBG_UNEXPECTED_STATE() \
	bt_dev_dbg(hdev, \
		   "Unexpected packet (%d) for state (%d). ", \
		   hci_dmp_cb(skb)->pkt_type, hdev->dump.state)

#define MAX_DEVCOREDUMP_HDR_SIZE	512	/* bytes */

static int hci_devcd_update_hdr_state(char *buf, size_t size, int state)
{
	int len = 0;

	if (!buf)
		return 0;

	len = scnprintf(buf, size, "Bluetooth devcoredump\nState: %d\n", state);

	return len + 1; /* scnprintf adds \0 at the end upon state rewrite */
}

/* Call with hci_dev_lock only. */
static int hci_devcd_update_state(struct hci_dev *hdev, int state)
{
	bt_dev_dbg(hdev, "Updating devcoredump state from %d to %d.",
		   hdev->dump.state, state);

	hdev->dump.state = state;

	return hci_devcd_update_hdr_state(hdev->dump.head,
					  hdev->dump.alloc_size, state);
}

static int hci_devcd_mkheader(struct hci_dev *hdev, struct sk_buff *skb)
{
	char dump_start[] = "--- Start dump ---\n";
	char hdr[80];
	int hdr_len;

	hdr_len = hci_devcd_update_hdr_state(hdr, sizeof(hdr),
					     HCI_DEVCOREDUMP_IDLE);
	skb_put_data(skb, hdr, hdr_len);

	if (hdev->dump.dmp_hdr)
		hdev->dump.dmp_hdr(hdev, skb);

	skb_put_data(skb, dump_start, strlen(dump_start));

	return skb->len;
}

/* Do not call with hci_dev_lock since this calls driver code. */
static void hci_devcd_notify(struct hci_dev *hdev, int state)
{
	if (hdev->dump.notify_change)
		hdev->dump.notify_change(hdev, state);
}

/* Call with hci_dev_lock only. */
void hci_devcd_reset(struct hci_dev *hdev)
{
	hdev->dump.head = NULL;
	hdev->dump.tail = NULL;
	hdev->dump.alloc_size = 0;

	hci_devcd_update_state(hdev, HCI_DEVCOREDUMP_IDLE);

	cancel_delayed_work(&hdev->dump.dump_timeout);
	skb_queue_purge(&hdev->dump.dump_q);
}

/* Call with hci_dev_lock only. */
static void hci_devcd_free(struct hci_dev *hdev)
{
	vfree(hdev->dump.head);

	hci_devcd_reset(hdev);
}

/* Call with hci_dev_lock only. */
static int hci_devcd_alloc(struct hci_dev *hdev, u32 size)
{
	hdev->dump.head = vmalloc(size);
	if (!hdev->dump.head)
		return -ENOMEM;

	hdev->dump.alloc_size = size;
	hdev->dump.tail = hdev->dump.head;
	hdev->dump.end = hdev->dump.head + size;

	hci_devcd_update_state(hdev, HCI_DEVCOREDUMP_IDLE);

	return 0;
}

/* Call with hci_dev_lock only. */
static bool hci_devcd_copy(struct hci_dev *hdev, char *buf, u32 size)
{
	if (hdev->dump.tail + size > hdev->dump.end)
		return false;

	memcpy(hdev->dump.tail, buf, size);
	hdev->dump.tail += size;

	return true;
}

/* Call with hci_dev_lock only. */
static bool hci_devcd_memset(struct hci_dev *hdev, u8 pattern, u32 len)
{
	if (hdev->dump.tail + len > hdev->dump.end)
		return false;

	memset(hdev->dump.tail, pattern, len);
	hdev->dump.tail += len;

	return true;
}
void hci_devcd_rx(struct hci_dev *hdev, const u8 *data, size_t count)
{
    if (!hci_devcd_enabled(hdev)) {
        bt_dev_err(hdev, "devcoredump not enabled");
        return;
    }

    hci_dev_lock(hdev);

    if (hdev->dump.busy) {
        bt_dev_err(hdev, "previous dump still in progress");
        hci_dev_unlock(hdev);
        return;
    }

    /* Update the dump buffer with new data */
    size_t space_left = hdev->dump.alloc_size - (hdev->dump.tail - hdev->dump.head);
    size_t to_copy = min(space_left, count);
    if (to_copy > 0) {
        memcpy(hdev->dump.tail, data, to_copy);
        hdev->dump.tail += to_copy;
    }

    /* Check if the buffer is full */
    if (to_copy < count) {
        bt_dev_warn(hdev, "devcoredump buffer overflow");
        hci_devcd_notify(hdev, HCI_DEVCOREDUMP_OVERFLOW);
        hci_devcd_reset(hdev);
    } else {
        /* Continue accepting data */
        schedule_work(&hdev->dump.dump_rx);
    }

    hci_dev_unlock(hdev);
}

void hci_devcd_reset(struct hci_dev *hdev)
{
    hci_dev_lock(hdev);

    hdev->dump.head = hdev->dump.buffer;
    hdev->dump.tail = hdev->dump.buffer;
    hdev->dump.busy = false;

    hci_dev_unlock(hdev);
}

bool hci_devcd_check_supported(struct hci_dev *hdev)
{
    /* Add additional checks for device support here if needed */
    return hdev->dump.supported;
}

void hci_devcd_notify(struct hci_dev *hdev, enum hci_devcd_event event)

{

    /* Implementation of notifications to the system or a logging service */
    switch (event) {
        case HCI_DEVCOREDUMP_OVERFLOW:
            bt_dev_err(hdev, "Core dump overflow occurred");
            break;
        case HCI_DEVCOREDUMP_TIMEOUT:
            bt_dev_err(hdev, "Core dump timeout occurred");
            break;
        default:
            bt_dev_dbg(hdev, "Unknown devcoredump event");
            break;
}

void hci_devcd_process_complete(struct hci_dev *hdev)

{
    if (!hci_devcd_enabled(hdev)) {
        bt_dev_err(hdev, "Devcoredump processing attempted on unsupported device");
        return;
    }

    hci_dev_lock(hdev);

    /* Check if the full dump has been collected */
    if ((hdev->dump.tail - hdev->dump.head) < hdev->dump.alloc_size) {
        bt_dev_warn(hdev, "Incomplete devcoredump collected");
        hci_devcd_notify(hdev, HCI_DEVCOREDUMP_INCOMPLETE);
    } else {
        bt_dev_info(hdev, "Devcoredump collected successfully, processing");
        hdev->dump.coredump(hdev->dump.head, hdev->dump.alloc_size);
    }

    /* Reset dump state after processing */
    hci_devcd_reset(hdev);

    hci_dev_unlock(hdev);
}

bool hci_devcd_process_command(struct hci_dev *hdev, const u8 *cmd, size_t cmd_len)
{
    /* Commands to control or query the core dump state */
    if (!hci_devcd_enabled(hdev)) {
        bt_dev_err(hdev, "Devcoredump command received for unsupported device");
        return false;
    }

    hci_dev_lock(hdev);

    if (memcmp(cmd, "RESET", min(cmd_len, 5)) == 0) {
        hci_devcd_reset(hdev);
        hci_dev_unlock(hdev);
        return true;
    } else if (memcmp(cmd, "STATUS", min(cmd_len, 6)) == 0) {
        size_t dump_size = hdev->dump.tail - hdev->dump.head;
        bt_dev_info(hdev, "Current devcoredump status: %zu bytes collected", dump_size);
        hci_dev_unlock(hdev);
        return true;
    }

    hci_dev_unlock(hdev);
    return false;
}

/* Call with hci_dev_lock only. */
static int hci_devcd_prepare(struct hci_dev *hdev, u32 dump_size)
{
	struct sk_buff *skb;
	int dump_hdr_size;
	int err = 0;

	skb = alloc_skb(MAX_DEVCOREDUMP_HDR_SIZE, GFP_ATOMIC);
	if (!skb)
		return -ENOMEM;

	dump_hdr_size = hci_devcd_mkheader(hdev, skb);

	if (hci_devcd_alloc(hdev, dump_hdr_size + dump_size)) {
		err = -ENOMEM;
		goto hdr_free;
	}

	/* Insert the device header */
	if (!hci_devcd_copy(hdev, skb->data, skb->len)) {
		bt_dev_err(hdev, "Failed to insert header");
		hci_devcd_free(hdev);

		err = -ENOMEM;
		goto hdr_free;
	}

hdr_free:
	kfree_skb(skb);

	return err;
}

static void hci_devcd_handle_pkt_init(struct hci_dev *hdev, struct sk_buff *skb)
{
	u32 dump_size;

	if (hdev->dump.state != HCI_DEVCOREDUMP_IDLE) {
		DBG_UNEXPECTED_STATE();
		return;
	}

	if (skb->len != sizeof(dump_size)) {
		bt_dev_dbg(hdev, "Invalid dump init pkt");
		return;
	}

	dump_size = get_unaligned_le32(skb_pull_data(skb, 4));
	if (!dump_size) {
		bt_dev_err(hdev, "Zero size dump init pkt");
		return;
	}

	if (hci_devcd_prepare(hdev, dump_size)) {
		bt_dev_err(hdev, "Failed to prepare for dump");
		return;
	}

	hci_devcd_update_state(hdev, HCI_DEVCOREDUMP_ACTIVE);
	queue_delayed_work(hdev->workqueue, &hdev->dump.dump_timeout,
			   hdev->dump.timeout);
}

static void hci_devcd_handle_pkt_skb(struct hci_dev *hdev, struct sk_buff *skb)
{
	if (hdev->dump.state != HCI_DEVCOREDUMP_ACTIVE) {
		DBG_UNEXPECTED_STATE();
		return;
	}

	if (!hci_devcd_copy(hdev, skb->data, skb->len))
		bt_dev_dbg(hdev, "Failed to insert skb");
}

static void hci_devcd_handle_pkt_pattern(struct hci_dev *hdev,
					 struct sk_buff *skb)
{
	struct hci_devcoredump_skb_pattern *pattern;

	if (hdev->dump.state != HCI_DEVCOREDUMP_ACTIVE) {
		DBG_UNEXPECTED_STATE();
		return;
	}

	if (skb->len != sizeof(*pattern)) {
		bt_dev_dbg(hdev, "Invalid pattern skb");
		return;
	}

	pattern = skb_pull_data(skb, sizeof(*pattern));

	if (!hci_devcd_memset(hdev, pattern->pattern, pattern->len))
		bt_dev_dbg(hdev, "Failed to set pattern");
}

static void hci_devcd_handle_pkt_complete(struct hci_dev *hdev,
					  struct sk_buff *skb)
{
	u32 dump_size;

	if (hdev->dump.state != HCI_DEVCOREDUMP_ACTIVE) {
		DBG_UNEXPECTED_STATE();
		return;
	}

	hci_devcd_update_state(hdev, HCI_DEVCOREDUMP_DONE);
	dump_size = hdev->dump.tail - hdev->dump.head;

	bt_dev_dbg(hdev, "complete with size %u (expect %zu)", dump_size,
		   hdev->dump.alloc_size);

	dev_coredumpv(&hdev->dev, hdev->dump.head, dump_size, GFP_KERNEL);
}

static void hci_devcd_handle_pkt_abort(struct hci_dev *hdev,
				       struct sk_buff *skb)
{
	u32 dump_size;

	if (hdev->dump.state != HCI_DEVCOREDUMP_ACTIVE) {
		DBG_UNEXPECTED_STATE();
		return;
	}

	hci_devcd_update_state(hdev, HCI_DEVCOREDUMP_ABORT);
	dump_size = hdev->dump.tail - hdev->dump.head;

	bt_dev_dbg(hdev, "aborted with size %u (expect %zu)", dump_size,
		   hdev->dump.alloc_size);

	/* Emit a devcoredump with the available data */
	dev_coredumpv(&hdev->dev, hdev->dump.head, dump_size, GFP_KERNEL);
}

/* Bluetooth devcoredump state machine.
 *
 * Devcoredump states:
 *
 *      HCI_DEVCOREDUMP_IDLE: The default state.
 *
 *      HCI_DEVCOREDUMP_ACTIVE: A devcoredump will be in this state once it has
 *              been initialized using hci_devcd_init(). Once active, the driver
 *              can append data using hci_devcd_append() or insert a pattern
 *              using hci_devcd_append_pattern().
 *
 *      HCI_DEVCOREDUMP_DONE: Once the dump collection is complete, the drive
 *              can signal the completion using hci_devcd_complete(). A
 *              devcoredump is generated indicating the completion event and
 *              then the state machine is reset to the default state.
 *
 *      HCI_DEVCOREDUMP_ABORT: The driver can cancel ongoing dump collection in
 *              case of any error using hci_devcd_abort(). A devcoredump is
 *              still generated with the available data indicating the abort
 *              event and then the state machine is reset to the default state.
 *
 *      HCI_DEVCOREDUMP_TIMEOUT: A timeout timer for HCI_DEVCOREDUMP_TIMEOUT sec
 *              is started during devcoredump initialization. Once the timeout
 *              occurs, the driver is notified, a devcoredump is generated with
 *              the available data indicating the timeout event and then the
 *              state machine is reset to the default state.
 *
 * The driver must register using hci_devcd_register() before using the hci
 * devcoredump APIs.
 */
void hci_devcd_rx(struct work_struct *work)
{
	struct hci_dev *hdev = container_of(work, struct hci_dev, dump.dump_rx);
	struct sk_buff *skb;
	int start_state;

	while ((skb = skb_dequeue(&hdev->dump.dump_q))) {
		/* Return if timeout occurs. The timeout handler function
		 * hci_devcd_timeout() will report the available dump data.
		 */
		if (hdev->dump.state == HCI_DEVCOREDUMP_TIMEOUT) {
			kfree_skb(skb);
			return;
		}

		hci_dev_lock(hdev);
		start_state = hdev->dump.state;

		switch (hci_dmp_cb(skb)->pkt_type) {
		case HCI_DEVCOREDUMP_PKT_INIT:
			hci_devcd_handle_pkt_init(hdev, skb);
			break;

		case HCI_DEVCOREDUMP_PKT_SKB:
			hci_devcd_handle_pkt_skb(hdev, skb);
			break;

		case HCI_DEVCOREDUMP_PKT_PATTERN:
			hci_devcd_handle_pkt_pattern(hdev, skb);
			break;

		case HCI_DEVCOREDUMP_PKT_COMPLETE:
			hci_devcd_handle_pkt_complete(hdev, skb);
			break;

		case HCI_DEVCOREDUMP_PKT_ABORT:
			hci_devcd_handle_pkt_abort(hdev, skb);
			break;

		default:
			bt_dev_dbg(hdev, "Unknown packet (%d) for state (%d). ",
				   hci_dmp_cb(skb)->pkt_type, hdev->dump.state);
			break;
		}

		hci_dev_unlock(hdev);
		kfree_skb(skb);

		/* Notify the driver about any state changes before resetting
		 * the state machine
		 */
		if (start_state != hdev->dump.state)
			hci_devcd_notify(hdev, hdev->dump.state);

		/* Reset the state machine if the devcoredump is complete */
		hci_dev_lock(hdev);
		if (hdev->dump.state == HCI_DEVCOREDUMP_DONE ||
		    hdev->dump.state == HCI_DEVCOREDUMP_ABORT)
			hci_devcd_reset(hdev);
		hci_dev_unlock(hdev);
	}
}
EXPORT_SYMBOL(hci_devcd_rx);

void hci_devcd_timeout(struct work_struct *work)
{
	struct hci_dev *hdev = container_of(work, struct hci_dev,
					    dump.dump_timeout.work);
	u32 dump_size;

	hci_devcd_notify(hdev, HCI_DEVCOREDUMP_TIMEOUT);

	hci_dev_lock(hdev);

	cancel_work(&hdev->dump.dump_rx);

	hci_devcd_update_state(hdev, HCI_DEVCOREDUMP_TIMEOUT);

	dump_size = hdev->dump.tail - hdev->dump.head;
	bt_dev_dbg(hdev, "timeout with size %u (expect %zu)", dump_size,
		   hdev->dump.alloc_size);

	/* Emit a devcoredump with the available data */
	dev_coredumpv(&hdev->dev, hdev->dump.head, dump_size, GFP_KERNEL);

	hci_devcd_reset(hdev);

	hci_dev_unlock(hdev);
}
EXPORT_SYMBOL(hci_devcd_timeout);

int hci_devcd_register(struct hci_dev *hdev, coredump_t coredump,
		       dmp_hdr_t dmp_hdr, notify_change_t notify_change)
{
	/* Driver must implement coredump() and dmp_hdr() functions for
	 * bluetooth devcoredump. The coredump() should trigger a coredump
	 * event on the controller when the device's coredump sysfs entry is
	 * written to. The dmp_hdr() should create a dump header to identify
	 * the controller/fw/driver info.
	 */
	if (!coredump || !dmp_hdr)
		return -EINVAL;

	hci_dev_lock(hdev);
	hdev->dump.coredump = coredump;
	hdev->dump.dmp_hdr = dmp_hdr;
	hdev->dump.notify_change = notify_change;
	hdev->dump.supported = true;
	hdev->dump.timeout = DEVCOREDUMP_TIMEOUT;
	hci_dev_unlock(hdev);

	return 0;
}
EXPORT_SYMBOL(hci_devcd_register);

static inline bool hci_devcd_enabled(struct hci_dev *hdev)
{
	return hdev->dump.supported;
}

int hci_devcd_init(struct hci_dev *hdev, u32 dump_size)
{
	struct sk_buff *skb;

	if (!hci_devcd_enabled(hdev))
		return -EOPNOTSUPP;

	skb = alloc_skb(sizeof(dump_size), GFP_ATOMIC);
	if (!skb)
		return -ENOMEM;

	hci_dmp_cb(skb)->pkt_type = HCI_DEVCOREDUMP_PKT_INIT;
	put_unaligned_le32(dump_size, skb_put(skb, 4));

	skb_queue_tail(&hdev->dump.dump_q, skb);
	queue_work(hdev->workqueue, &hdev->dump.dump_rx);

	return 0;
}
EXPORT_SYMBOL(hci_devcd_init);

int hci_devcd_append(struct hci_dev *hdev, struct sk_buff *skb)
{
	if (!skb)
		return -ENOMEM;

	if (!hci_devcd_enabled(hdev)) {
		kfree_skb(skb);
		return -EOPNOTSUPP;
	}

	hci_dmp_cb(skb)->pkt_type = HCI_DEVCOREDUMP_PKT_SKB;

	skb_queue_tail(&hdev->dump.dump_q, skb);
	queue_work(hdev->workqueue, &hdev->dump.dump_rx);

	return 0;
}
EXPORT_SYMBOL(hci_devcd_append);

int hci_devcd_append_pattern(struct hci_dev *hdev, u8 pattern, u32 len)
{
	struct hci_devcoredump_skb_pattern p;
	struct sk_buff *skb;

	if (!hci_devcd_enabled(hdev))
		return -EOPNOTSUPP;

	skb = alloc_skb(sizeof(p), GFP_ATOMIC);
	if (!skb)
		return -ENOMEM;

	p.pattern = pattern;
	p.len = len;

	hci_dmp_cb(skb)->pkt_type = HCI_DEVCOREDUMP_PKT_PATTERN;
	skb_put_data(skb, &p, sizeof(p));

	skb_queue_tail(&hdev->dump.dump_q, skb);
	queue_work(hdev->workqueue, &hdev->dump.dump_rx);

	return 0;
}
EXPORT_SYMBOL(hci_devcd_append_pattern);

int hci_devcd_complete(struct hci_dev *hdev)
{
	struct sk_buff *skb;

	if (!hci_devcd_enabled(hdev))
		return -EOPNOTSUPP;

	skb = alloc_skb(0, GFP_ATOMIC);
	if (!skb)
		return -ENOMEM;

	hci_dmp_cb(skb)->pkt_type = HCI_DEVCOREDUMP_PKT_COMPLETE;

	skb_queue_tail(&hdev->dump.dump_q, skb);
	queue_work(hdev->workqueue, &hdev->dump.dump_rx);

	return 0;
}
EXPORT_SYMBOL(hci_devcd_complete);

int hci_devcd_abort(struct hci_dev *hdev)
{
	struct sk_buff *skb;

	if (!hci_devcd_enabled(hdev))
		return -EOPNOTSUPP;

	skb = alloc_skb(0, GFP_ATOMIC);
	if (!skb)
		return -ENOMEM;

	hci_dmp_cb(skb)->pkt_type = HCI_DEVCOREDUMP_PKT_ABORT;

	skb_queue_tail(&hdev->dump.dump_q, skb);
	queue_work(hdev->workqueue, &hdev->dump.dump_rx);

	return 0;
}
EXPORT_SYMBOL(hci_devcd_abort);
