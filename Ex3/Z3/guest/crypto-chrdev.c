/*
 * crypto-chrdev.c
 *
 * Implementation of character devices
 * for virtio-crypto device 
 *
 * Vangelis Koukis <vkoukis@cslab.ece.ntua.gr>
 * Dimitris Siakavaras <jimsiak@cslab.ece.ntua.gr>
 * Stefanos Gerangelos <sgerag@cslab.ece.ntua.gr>
 *
 */
#include <linux/cdev.h>
#include <linux/poll.h>
#include <linux/sched.h>
#include <linux/module.h>
#include <linux/wait.h>
#include <linux/virtio.h>
#include <linux/virtio_config.h>

#include "crypto.h"
#include "crypto-chrdev.h"
#include "debug.h"

#include "cryptodev.h"

/*
 * Global data
 */
struct cdev crypto_chrdev_cdev;

/**
 * Given the minor number of the inode return the crypto device 
 * that owns that number.
 **/
static struct crypto_device *get_crypto_dev_by_minor(unsigned int minor)
{
	struct crypto_device *crdev;
	unsigned long flags;

	debug("Entering");

	spin_lock_irqsave(&crdrvdata.lock, flags);
	list_for_each_entry(crdev, &crdrvdata.devs, list) {
		if (crdev->minor == minor)
			goto out;
	}
	crdev = NULL;

out:
	spin_unlock_irqrestore(&crdrvdata.lock, flags);

	debug("Leaving");
	return crdev;
}

/*************************************
 * Implementation of file operations
 * for the Crypto character device
 *************************************/

static int crypto_chrdev_open(struct inode *inode, struct file *filp)
{
	int ret = 0;
	unsigned int len;
	struct crypto_open_file *crof;
	struct crypto_device *crdev;
	struct virtqueue *vq;
	unsigned int *syscall_type;
	int *host_fd;
	struct scatterlist syscall_type_sg, host_fd_sg, *sgs[2];
	unsigned int num_out = 0;
	unsigned int num_in = 0;

	debug("Entering");

	syscall_type = kzalloc(sizeof(*syscall_type), GFP_KERNEL);
	*syscall_type = VIRTIO_CRYPTO_SYSCALL_OPEN;
	host_fd = kzalloc(sizeof(*host_fd), GFP_KERNEL);
	*host_fd = -1;

	if ((ret = nonseekable_open(inode, filp)) < 0) {
		ret = -ENODEV;
		goto fail;
	}

	/* Associate this open file with the relevant crypto device. */
	crdev = get_crypto_dev_by_minor(iminor(inode));
	if (!crdev) {
		debug("Could not find crypto device with %u minor",
		      iminor(inode));
		ret = -ENODEV;
		goto fail;
	}

	crof = kzalloc(sizeof(*crof), GFP_KERNEL);
	if (!crof) {
		ret = -ENOMEM;
		goto fail;
	}
	crof->crdev = crdev;
	crof->host_fd = -1;
	filp->private_data = crof;
	vq = crdev->vq;

	/**
	 * We need two sg lists, one for syscall_type and one to get the
	 * file descriptor from the host.
	 **/
	/* ?? */

	sg_init_one(&syscall_type_sg, syscall_type, sizeof(*syscall_type));
	sgs[num_out++] = &syscall_type_sg;

	sg_init_one(&host_fd_sg, host_fd, sizeof(*host_fd));
	sgs[num_out + num_in++] = &host_fd_sg;

	/**
	 * Wait for the host to process our data.
	 **/
	/* ?? */
	if(down_interruptible(&crdev->lock)) {
		ret = -ERESTARTSYS;
		debug("open: down_interruptible");
		goto fail;
	}
	ret = virtqueue_add_sgs(vq, sgs, num_out, num_in,
	                        &syscall_type_sg, GFP_ATOMIC);
	if (ret) {
		debug("open: add_sgs failed");
		up(&crdev->lock);
		goto fail;
	}

	if(!virtqueue_kick(vq)) {
		debug("open: kick failed");
		up(&crdev->lock);
		ret = -1;
		goto fail;
	}

	while (virtqueue_get_buf(vq, &len) == NULL)
		/* do nothing */;
	up(&crdev->lock);


	/* If host failed to open() return -ENODEV. */
	/* ?? */
	if (*host_fd < 0) {
		ret = -ENODEV;
		debug("open: host_fd < 0");
		goto fail;
	}

	crof->host_fd = *host_fd;

fail:
	kfree(syscall_type);
	kfree(host_fd);
	debug("Leaving");
	return ret;
}

static int crypto_chrdev_release(struct inode *inode, struct file *filp)
{
	int ret = 0;
	struct crypto_open_file *crof = filp->private_data;
	struct crypto_device *crdev = crof->crdev;
	struct virtqueue *vq = crdev->vq;
	unsigned int *syscall_type;
	int *host_fd;
	struct scatterlist syscall_type_sg, host_fd_sg, *sgs[2];
	unsigned int num_out = 0, num_in = 0, len;

	debug("Entering");

	syscall_type = kzalloc(sizeof(*syscall_type), GFP_KERNEL);
	*syscall_type = VIRTIO_CRYPTO_SYSCALL_CLOSE;
	host_fd = kzalloc(sizeof(*host_fd), GFP_KERNEL);
	*host_fd = crof->host_fd;

	/**
	 * Send data to the host.
	 **/
	/* ?? */

	sg_init_one(&syscall_type_sg, syscall_type, sizeof(*syscall_type));
	sgs[num_out++] = &syscall_type_sg;

	sg_init_one(&host_fd_sg, host_fd, sizeof(*host_fd));
	sgs[num_out++] = &host_fd_sg;

	/**
	 * Wait for the host to process our data.
	 **/
	/* ?? */
	if(down_interruptible(&crdev->lock)) {
		ret = -ERESTARTSYS;
		debug("release: down_interruptible");
		goto fail;
	}
	ret = virtqueue_add_sgs(vq, sgs, num_out, num_in,
	                        &syscall_type_sg, GFP_ATOMIC);
	if (ret) {
		debug("release: add_sgs failed");
		up(&crdev->lock);
		goto fail;
	}
	if(!virtqueue_kick(vq)) {
		debug("release: kick failed");
		up(&crdev->lock);
		ret = -1;
		goto fail;
	}
	while (virtqueue_get_buf(vq, &len) == NULL)
		/* do nothing */;
	up(&crdev->lock);

fail:
	kfree(syscall_type);
	kfree(host_fd);

	kfree(crof);
	debug("Leaving");
	return ret;

}

static long crypto_chrdev_ioctl(struct file *filp, unsigned int cmd,
				unsigned long arg)
{
	long ret = 0;
	struct crypto_open_file *crof = filp->private_data;
	struct crypto_device *crdev = crof->crdev;
	struct virtqueue *vq = crdev->vq;
	struct scatterlist syscall_type_sg, host_fd_sg, ioctl_cmd_sg,
			   host_return_val_sg, *sgs[8];
	unsigned int num_out = 0, num_in = 0, len;
	unsigned int *syscall_type, *ioctl_cmd;
	int *host_fd, *host_return_val;
	struct session_op *session_op = NULL;
	unsigned char *session_key = NULL, *src= NULL, *iv = NULL, *dst = NULL,
		      *user_key_ptr = NULL, *user_dst_ptr = NULL;
	struct scatterlist session_op_sg, session_key_sg, ses_id_sg,
			   crypt_op_sg, src_sg, iv_sg, dst_sg;
	struct crypt_op *crypt_op = NULL;
	__u32 *ses_id = NULL, keylen, datalen = 0;
	debug("Entering");

	/**
	 * Allocate all data that will be sent to the host.
	 **/

	syscall_type = kzalloc(sizeof(*syscall_type), GFP_KERNEL);
	*syscall_type = VIRTIO_CRYPTO_SYSCALL_IOCTL;

	host_fd = kzalloc(sizeof(*host_fd), GFP_KERNEL);
	*host_fd = crof->host_fd;

	ioctl_cmd = kzalloc(sizeof(*ioctl_cmd), GFP_KERNEL);
	*ioctl_cmd = cmd;

	host_return_val = kzalloc(sizeof(*host_return_val), GFP_KERNEL);
	*host_return_val = -1;


	/**
	 *  These are common to all ioctl commands.
	 **/
	sg_init_one(&syscall_type_sg, syscall_type, sizeof(*syscall_type));
	sgs[num_out++] = &syscall_type_sg;
	/* ?? */
	sg_init_one(&host_fd_sg, host_fd, sizeof(*host_fd));
	sgs[num_out++] = &host_fd_sg;

	sg_init_one(&ioctl_cmd_sg, ioctl_cmd, sizeof(*ioctl_cmd));
	sgs[num_out++] = &ioctl_cmd_sg;

	/**
	 *  Add all the cmd specific sg lists.
	 **/

	switch (cmd) {
	case CIOCGSESSION:
		//debug("CIOCGSESSION");
		session_op = kzalloc(sizeof(*session_op), GFP_KERNEL);
		if (copy_from_user(session_op, (void *)arg, sizeof(*session_op))) {
			ret = -EFAULT;
			debug("copy_from_user session_op failed");
			kfree(session_op);
			goto fail;
		}
		user_key_ptr = session_op->key;
		keylen = session_op->keylen;
		session_key = kzalloc(sizeof(*session_key)*keylen, GFP_KERNEL);
		if (copy_from_user(session_key, session_op->key, sizeof(*session_key)*keylen)) {
			ret = -EFAULT;
			debug("copy_from_user session_key failed");
			kfree(session_op);
			kfree(session_key);
			goto fail;
		}
		session_op->key = session_key;

		sg_init_one(&session_key_sg, session_key, sizeof(*session_key)*keylen);
		sgs[num_out++] = &session_key_sg;

		sg_init_one(&session_op_sg, session_op, sizeof(*session_op));
		sgs[num_out + num_in++] = &session_op_sg;

		break;

	case CIOCFSESSION:
		//debug("CIOCFSESSION");
		ses_id = kzalloc(sizeof(*ses_id), GFP_KERNEL);
		if (copy_from_user(ses_id, (void *) arg, sizeof(*ses_id))) {
			ret = -EFAULT;
			debug("copy_from_user ses_id failed");
			kfree(ses_id);
			goto fail;

		}

		sg_init_one(&ses_id_sg, ses_id, sizeof(*ses_id));
		sgs[num_out++] = &ses_id_sg;

		break;

	case CIOCCRYPT:
		//debug("CIOCCRYPT");

		crypt_op = kzalloc(sizeof(*crypt_op), GFP_KERNEL);
		if (copy_from_user(crypt_op, (void *) arg, sizeof(*crypt_op))) {
			ret = -EFAULT;
			debug("copy_from_user crypt_op failed");
			kfree(crypt_op);
			goto fail;
		}
		user_dst_ptr = crypt_op->dst;
		datalen = crypt_op->len;

		src = kzalloc(sizeof(*src)*datalen, GFP_KERNEL);
		if (copy_from_user(src, crypt_op->src, sizeof(*src)*datalen)) {
			ret = -EFAULT;
			debug("copy_from_user src failed");
			kfree(crypt_op);
			kfree(src);
			goto fail;
		}
		crypt_op->src = src;

		iv = kzalloc(sizeof(*iv)*16, GFP_KERNEL);  // oxi panta 16 -> ????
		if (copy_from_user(iv, crypt_op->iv, sizeof(*iv)*16)) {
			ret = -EFAULT;
			debug("copy_from_user iv failed");
			kfree(crypt_op);
			kfree(src);
			kfree(iv);
			goto fail;
		}
		crypt_op->iv = iv;

		dst = kzalloc(sizeof(*dst)*datalen, GFP_KERNEL);
		crypt_op->dst = dst;


		sg_init_one(&crypt_op_sg, crypt_op, sizeof(*crypt_op));
		sgs[num_out++] = &crypt_op_sg;

		sg_init_one(&src_sg, src, sizeof(*src)*datalen);
		sgs[num_out++] = &src_sg;

		sg_init_one(&iv_sg, iv, sizeof(*iv)*16);  //16 ??
		sgs[num_out++] = &iv_sg;

		sg_init_one(&dst_sg, dst, sizeof(*dst)*datalen);
		sgs[num_out + num_in++] = &dst_sg;

		break;

	default:
		debug("Unsupported ioctl command");

		break;
	}

	sg_init_one(&host_return_val_sg, host_return_val, sizeof(*host_return_val));
	sgs[num_out + num_in++] = &host_return_val_sg;


	/**
	 * Wait for the host to process our data.
	 **/
	/* ?? */
	/* ?? Lock ?? */
	if(down_interruptible(&crdev->lock)) {
		ret = -ERESTARTSYS;
		goto fail;
	}
	ret = virtqueue_add_sgs(vq, sgs, num_out, num_in,
				&syscall_type_sg, GFP_ATOMIC);
	if (ret) {
		debug("release: add_sgs failed");
		up(&crdev->lock);
		goto fail;
	}
	if(!virtqueue_kick(vq)) {
		debug("release: kick failed");
		up(&crdev->lock);
		ret = -1;
		goto fail;
	}
	while (virtqueue_get_buf(vq, &len) == NULL)
		/* do nothing */;
	up(&crdev->lock);

	ret = *host_return_val;
	switch (cmd) {
	case CIOCGSESSION:
		session_op->key = user_key_ptr;
		if (copy_to_user((void *) arg, session_op, sizeof(*session_op))) {
			ret = -EFAULT;
			debug("copy_to_user session_op failed");
		}
		kfree(session_op);
		kfree(session_key);

		break;

	case CIOCFSESSION:
		kfree(ses_id);

		break;

	case CIOCCRYPT:
		if (copy_to_user(user_dst_ptr, dst, sizeof(*dst)*datalen)) {
			ret = -EFAULT;
			debug("copy_to_user dst failed");
		}
		kfree(crypt_op);
		kfree(src);
		kfree(iv);
		kfree(dst);

		break;

	default:
		break;
	}


fail:
	kfree(syscall_type);
	kfree(host_fd);
	kfree(ioctl_cmd);
	kfree(host_return_val);

	debug("Leaving");

	return ret;
}

static ssize_t crypto_chrdev_read(struct file *filp, char __user *usrbuf, 
                                  size_t cnt, loff_t *f_pos)
{
	debug("Entering");
	debug("Leaving");
	return -EINVAL;
}

static struct file_operations crypto_chrdev_fops = 
{
	.owner          = THIS_MODULE,
	.open           = crypto_chrdev_open,
	.release        = crypto_chrdev_release,
	.read           = crypto_chrdev_read,
	.unlocked_ioctl = crypto_chrdev_ioctl,
};

int crypto_chrdev_init(void)
{
	int ret;
	dev_t dev_no;
	unsigned int crypto_minor_cnt = CRYPTO_NR_DEVICES;
	
	debug("Initializing character device...");
	cdev_init(&crypto_chrdev_cdev, &crypto_chrdev_fops);
	crypto_chrdev_cdev.owner = THIS_MODULE;
	
	dev_no = MKDEV(CRYPTO_CHRDEV_MAJOR, 0);
	ret = register_chrdev_region(dev_no, crypto_minor_cnt, "crypto_devs");
	if (ret < 0) {
		debug("failed to register region, ret = %d", ret);
		goto out;
	}
	ret = cdev_add(&crypto_chrdev_cdev, dev_no, crypto_minor_cnt);
	if (ret < 0) {
		debug("failed to add character device");
		goto out_with_chrdev_region;
	}

	debug("Completed successfully");
	return 0;

out_with_chrdev_region:
	unregister_chrdev_region(dev_no, crypto_minor_cnt);
out:
	return ret;
}

void crypto_chrdev_destroy(void)
{
	dev_t dev_no;
	unsigned int crypto_minor_cnt = CRYPTO_NR_DEVICES;

	debug("entering");
	dev_no = MKDEV(CRYPTO_CHRDEV_MAJOR, 0);
	cdev_del(&crypto_chrdev_cdev);
	unregister_chrdev_region(dev_no, crypto_minor_cnt);
	debug("leaving");
}
