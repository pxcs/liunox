```
linux/
│
├── arch/                   
│   ├── x86/                 
│   ├── arm/                 
│   └── ...                   
│
├── block/                
│
├── certs/          
│
├── crypto/            
│
├── Documentation/        
│
├── drivers/            
│   ├── gpu/               
│   ├── net/            
│   ├── media/          
│   └── ...              
│
├── fs/                 
│   ├── ext4/            
│   ├── nfs/         
│   └── ...          
│
├── include/              
│   ├── linux/            
│   ├── asm-generic/       
│   └── ...                 
│
├── init/                
│
├── ipc/                    
│
├── kernel/             
│   ├── sched/           
│   ├── power/           
│   └── ...              
│
├── lib/            
│
├── mm/                 
│
├── net/                  
│   ├── ipv4/            
│   ├── ipv6/          
│   └── ...       
│
├── scripts/            
│
├── security/       
│
├── sound/             
│
├── tools/           
│
├── usr/                
│
└── virt/               
```
#### More detail kernel-->Key directories within the Linux kernel
```
linux/
│
├── arch/               
│   ├── x86/            
│   │   ├── boot/  ✔       
│   │   ├── kernel/  ✔     
│   │   └── mm/          
│   ├── arm/            
│   └── ...            
│
├── block/             
│   ├── blk-core.c     
│   ├── blk-mq.c          
│   └── blk-settings.c   
│
├── certs/          
│   ├── x509_certificate_list 
│   └── blacklisted_hashes  
│
├── crypto/                
│   ├── aes.c              
│   ├── api.c  ✔             
│   └── sha256_generic.c   
│
├── Documentation/         
│   ├── filesystems/     
│   ├── networking/        
│   └── scheduler/       
│
├── drivers/           
│   ├── gpu/              
│   ├── net/      
│   ├── pci/             
│   └── usb/         
│
├── fs/          
│   ├── ext4/          
│   ├── super.c     
│   └── inode.c  ✔            
│
├── include/            
│   ├── linux/        
│   ├── asm-generic/     
│   └── net/            
│
├── ipc/                
│   ├── semaphore.c      
│   ├── msg.c             
│   └── shm.c            
│
├── kernel/            
│   ├── sched/         
│   ├── sync.c        
│   └── pid.c        
│
├── mm/               
│   ├── memory.c       
│   ├── mmap.c          
│   └── page_alloc.c       
│
├── net/  ✔     
│   ├── ipv4/           
│   ├── ipv6/      
│   └── socket.c       
│
├── scripts/          
│   ├── config/         
│   └── kconfig/        
│
├── security/     
│   ├── selinux/       
│   ├── apparmor/         
│   └── keys/             
│
├── sound/              
│   ├── core/             
│   └── drivers/     
│
├── tools/              
│   ├── perf/          
│   └── testing/      
│
├── usr/                
│   └── initramfs/      
│
└── virt/       
    ├── kvm/               
    └── vboxguest/     

```
