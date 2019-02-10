#include "types.h"
#include "defs.h"
#include "param.h"
#include "memlayout.h"
#include "mmu.h"
#include "proc.h"
#include "x86.h"
#include "traps.h"
#include "spinlock.h"

// Interrupt descriptor table (shared by all CPUs).
struct gatedesc idt[256];
extern uint vectors[];  // in vectors.S: array of 256 entry pointers
struct spinlock tickslock;
uint ticks;

void
tvinit(void)
{
  int i;

  for(i = 0; i < 256; i++)
    SETGATE(idt[i], 0, SEG_KCODE<<3, vectors[i], 0);
  SETGATE(idt[T_SYSCALL], 1, SEG_KCODE<<3, vectors[T_SYSCALL], DPL_USER);

  initlock(&tickslock, "time");
}

void
idtinit(void)
{
  lidt(idt, sizeof(idt));
}

//PAGEBREAK: 41
void
trap(struct trapframe *tf)
{
  if(tf->trapno == T_SYSCALL){
    if(myproc()->killed)
      exit();
    myproc()->tf = tf;
    syscall();
    if(myproc()->killed)
      exit();
    return;
  }

  switch(tf->trapno){
  case T_IRQ0 + IRQ_TIMER:
    if(cpuid() == 0){
      acquire(&tickslock);
      ticks++;
      wakeup(&ticks);
      release(&tickslock);
    }
    lapiceoi();
    break;
  case T_IRQ0 + IRQ_IDE:
    ideintr();
    lapiceoi();
    break;
  case T_IRQ0 + IRQ_IDE+1:
    // Bochs generates spurious IDE1 interrupts.
    break;
  case T_IRQ0 + IRQ_KBD:
    kbdintr();
    lapiceoi();
    break;
  case T_IRQ0 + IRQ_COM1:
    uartintr();
    lapiceoi();
    break;
  case T_IRQ0 + 7:
  case T_IRQ0 + IRQ_SPURIOUS:
    cprintf("cpu%d: spurious interrupt at %x:%x\n",
            cpuid(), tf->cs, tf->eip);
    lapiceoi();
    break;

  //PAGEBREAK: 13
  default:
    if(myproc() == 0 || (tf->cs&3) == 0){
      // In kernel, it must be our mistake.
      cprintf("unexpected trap %d from cpu %d eip %x (cr2=0x%x)\n",
              tf->trapno, cpuid(), tf->eip, rcr2());
      panic("trap");
    }
    // In user space, assume process misbehaved.
    cprintf("pid %d %s: trap %d err %d on cpu %d "
            "eip 0x%x addr 0x%x--kill proc\n",
            myproc()->pid, myproc()->name, tf->trapno,
            tf->err, cpuid(), tf->eip, rcr2());
    myproc()->killed = 1;
  }

  // Force process exit if it has been killed and is in user space.
  // (If it is still executing in the kernel, let it keep running
  // until it gets to the regular system call return.)
  if(myproc() && myproc()->killed && (tf->cs&3) == DPL_USER)
    exit();

  // Force process to give up CPU on clock tick.
  // If interrupts were on while locks held, would need to check nlock.
  if(myproc() && myproc()->state == RUNNING &&
     tf->trapno == T_IRQ0+IRQ_TIMER)
    yield();

  // Check if the process has been killed since we yielded
  if(myproc() && myproc()->killed && (tf->cs&3) == DPL_USER)
    exit();
}



void 
B_input(struct pkt packet)
{
    printf("exp: %d reality: %d\n",expectedseqnum,packet.seqnum);


    if(packet.checksum!=createChecksum(packet))
    {



        printf("                    in receiver side corrupt PKT%d found\n",packet.seqnum);
        fprintf(fptr,"                  in receiver side corrupt PKT%d found\n",packet.seqnum);
        if(firstCorrectPacket==1)
        {
            printf("                    Re-Sending ACK: %d\n",sendPkt.seqnum);
            fprintf(fptr,"                    Re-Sending ACK: %d\n",sendPkt.seqnum);
            tolayer3(1,sendPkt);
        }


    }

    else if(packet.seqnum!=expectedseqnum)
    {
        printf("                    In receiver side unexpected PKT%d found expected PKT:%d\n",packet.seqnum,expectedseqnum);
        fprintf(fptr,"                    In receiver side unexpected PKT%d found expected PKT:%d\n",packet.seqnum,expectedseqnum);
        if(firstCorrectPacket==1)
        {
            printf("                    Re-Sending ACK: %d\n",sendPkt.seqnum);
            fprintf(fptr,"                    Re-Sending ACK: %d\n",sendPkt.seqnum);
            tolayer3(1,sendPkt);
        }
        //  tolayer3(1,sendPkt);


        //return;
    }


    else
    {



        //  printf("Packet %d recvd\n",packet.seqnum);
        tolayer5(1,packet.payload);
        sendPkt.seqnum=packet.seqnum;
        sendPkt.acknum=sendPkt.seqnum;
        strcpy(sendPkt.payload,packet.payload);
        sendPkt.checksum=createChecksum(packet);
        printf("                    ACK%d Sent\n",packet.seqnum);
        fprintf(fptr,"                  ACK%d Sent\n",packet.seqnum);
        firstCorrectPacket=1;
        tolayer3(1,sendPkt);
        expectedseqnum=(expectedseqnum+1)%seqSize;
        currentReceiverWindow();
    }//waiting=true;
}

/* called when B's timer goes off */
void 
B_timerinterrupt(void)
{
    printf("  B_timer interrupt: B doesn't have a timer. ignore.\n");
}


