# ooows-flag-baby challenge

This was the first challenge in a series of virtualization challenges. 
As the name implies, the challenge was meant to be a simple starter/warmup challenge. 
On the first day I started looking at the challenge and found that I was pretty much out of my comfort zone and a bit clueless.

Luckily there were others on the team that knew what was going on. 
However, I felt pretty inadequate for not being able to solve this, so I made it a personal goal to solve this one later once the competition was over.

## TLDR:
 - Challenge is to interface with I/O ports and retrieve flag  
- Create MBR with custom code that
  - interfaces with I/O port connected to `noflag.sh`
  - sends data to program FILENAME (beware of the filter)
  - send magic to trigger file open
  - read back flag contents
  - output flag back out to the serial port via I/O port
- View flag via web interface serial port

## High Level Overview:

Here is a high level overview of what is running in the container, and what the various binaries/scripts do. 
```
┌─────────────────┬──────────────────────────────────────────────────────────────────────────────────────────────────────────────┐
│"ooows" Container│                                                                                                              │
├─────────────────┘                                                                                                              │
│                                                                                                                                │
│                                                           ┌───────────────────────┬─────────────────────────────────────────┐  │
│   devices.config   // definition of devices and mem map   │ VM spawned via vmm.py │                                         │  │
│   Dockerfile       // used to build the container         ├───────────────────────┘                                         │  │
│   supervisord.conf // used to start web app               │                                                                 │  │
│   vmm              // binary to interface with /dev/kvm   │  - devices.config defines io port accesses to external scripts  │  │
│                                                           │  - custom bios written by ooo                                   │  │
│                                                           │  - Disk uploaded by user and attached to VM                     │  │
│   web                                                     │                                                                 │  │
│    | app.py        // main web app                        │                                                                 │  │
│    | console.py                                           │                                                                 │  │
│    | init-db.py                                           │                                                                 │  │
│    | schema.sql                                           │                                                                 │  │
│    | video.py                                             │                                                                 │  │
│    | vmm.py        // vmmWorker (invocation of vmm)       │                                                                 │  │
│                                                           │                                                                 │  │
│                                                           │                                                                 │  │
│   devices-bin                                             │                                                                 │  │
│    | noflag        ──┐                                    │                                                                 │  │
│    | noflag.sh       │        attached to vm io           │                                                                 │  │
│    | ooowsdisk.py    ├────────────────────────────────────┤                                                                 │  │
│    | ooowsserial.py  │                                    │                                                                 │  │
│    | vga           ──┘                                    │                                                                 │  │
│                                                           │                                                                 │  │
│                                                           │                                                                 │  │
│   bios                                                    │                                                                 │  │
│    | bios                                                 │                                                                 │  │
│                                                           │                                                                 │  │
│                                                           │                                                                 │  │
│                                                           │                                                                 │  │
│                                                           └─────────────────────────────────────────────────────────────────┘  │
│                                                                                                                                │
└────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┘
```

The web interface is nice and simple.

![WebInterface](./images/web_interface.png) 

The `Upload a virtual disk` button allows us to upload a disk image. 
Once uploaded, a VM shows up that can be started and the boot process can be observed via either the `Video` button

![VM Video](./images/web_video_buffer.png).

By default, nothing shows up on the serial console. This is because the `bios` outputs to `vga` and doesn't do anything with the serial interface.

So now where do we start?

### Learn about the MBR
