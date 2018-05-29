/*
 * fs/sdcardfs/main.c
 *
 * Copyright (c) 2013 Samsung Electronics Co. Ltd
 *   Authors: Daeho Jeong, Woojoong Lee, Seunghwan Hyun,
 *               Sunghwan Yun, Sungjong Seo
 *
 * This program has been developed as a stackable file system based on
 * the WrapFS which written by
 *
 * Copyright (c) 1998-2011 Erez Zadok
 * Copyright (c) 2009     Shrikar Archak
 * Copyright (c) 2003-2011 Stony Brook University
 * Copyright (c) 2003-2011 The Research Foundation of SUNY
 *
 * This file is dual licensed.  It may be redistributed and/or modified
 * under the terms of the Apache 2.0 License OR version 2 of the GNU
 * General Public License.
 */

#include "sdcardfs.h"
#include <linux/module.h>
#include <linux/types.h>
#include <linux/parser.h>
#include "../internal.h"
#include "version.h"

enum {
	Opt_uid,
	Opt_gid,
	Opt_userid,
	Opt_sdfs_gid,
	Opt_sdfs_mask,
	Opt_multi_user,
	Opt_owner_user,
	Opt_debug,
	Opt_mask,
	Opt_multiuser,
	Opt_userid,
	Opt_reserved_mb,
	Opt_gid_derivation,
	Opt_err,
};

static const match_table_t sdcardfs_tokens = {
	{Opt_uid, "uid=%u"},
	{Opt_gid, "gid=%u"},
	{Opt_userid, "userid=%u"},
	{Opt_sdfs_gid, "sdfs_gid=%u"},
	{Opt_sdfs_mask, "sdfs_mask=%u"},
	{Opt_multi_user, "multi_user"},
	{Opt_owner_user, "owner_user=%u"},
	{Opt_debug, "debug"},
	{Opt_mask, "mask=%u"},
	{Opt_userid, "userid=%d"},
	{Opt_multiuser, "multiuser"},
	{Opt_gid_derivation, "derive_gid"},
	{Opt_reserved_mb, "reserved_mb=%u"},
	{Opt_label, "label=%s"},
	{Opt_type, "type=%s"},
	{Opt_err, NULL}
};

static int parse_options(struct super_block *sb, char *options, int silent,
				int *debug, struct sdcardfs_vfsmount_options *vfsopts,
				struct sdcardfs_mount_options *opts)
{
	char *p;
	substring_t args[MAX_OPT_ARGS];
	int option;
	char *string_option;
	char *label;

	/* by default, we use AID_MEDIA_RW as uid, gid */
	opts->fs_low_uid = AID_MEDIA_RW;
	opts->fs_low_gid = AID_MEDIA_RW;
	vfsopts->mask = 0;
	opts->multiuser = false;
	opts->fs_user_id = 0;
	vfsopts->gid = 0;
	/* by default, 0MB is reserved */
	opts->reserved_mb = 0;
	/* by default, gid derivation is off */
	opts->gid_derivation = false;

	*debug = 0;

	if (!options)
		return 0;

	while ((p = strsep(&options, ",")) != NULL) {
		int token;

		if (!*p)
			continue;

		token = match_token(p, sdcardfs_tokens, args);

		switch (token) {
		case Opt_debug:
			*debug = 1;
			break;
		case Opt_uid:
			if (match_int(&args[0], &option))
				return 0;
			opts->fs_low_uid = option;
			break;
		case Opt_gid:
			if (match_int(&args[0], &option))
				return 0;
			opts->fs_low_gid = option;
			break;
		case Opt_userid:
			if (match_int(&args[0], &option))
				return 0;
			vfsopts->gid = option;
			break;
		case Opt_sdfs_gid:
			if (match_int(&args[0], &option))
				return 0;
			opts->sdfs_gid = option;
			break;
		case Opt_sdfs_mask:
			if (match_octal(&args[0], &option))
				return 0;
			opts->sdfs_mask = option;
			break;
		case Opt_multi_user:
			opts->multi_user = 1;
			break;
		case Opt_owner_user:
			if (match_int(&args[0], &option))
				return 0;
			vfsopts->mask = option;
			break;
		case Opt_lower_fs:
			string_option = match_strdup(&args[0]);
			if (!string_option)
				return -ENOMEM;
			if (!strcmp("ext4", string_option)) {
				opts->lower_fs = LOWER_FS_EXT4;
			} else if (!strcmp("exfat", string_option)) {
				opts->lower_fs = LOWER_FS_EXFAT;
			} else if (!strcmp("fat", string_option) || !strcmp("vfat", string_option)) {
				opts->lower_fs = LOWER_FS_FAT;
			} else if (!strcmp("ntfs", string_option)) {
				opts->lower_fs = LOWER_FS_NTFS;
			} else {
				kfree(string_option);
				goto invalid_option;
			}
			kfree(string_option);
			break;
		case Opt_reserved_mb:
			if (match_int(&args[0], &option))
				return 0;
			opts->reserved_mb = option;
			break;
		case Opt_gid_derivation:
			opts->gid_derivation = true;
			break;
		/* unknown option */
		default:
			if (!silent)
				pr_err("Unrecognized mount option \"%s\" or missing value", p);
			return -EINVAL;
		}
	}

	if (*debug) {
		pr_info("sdcardfs : options - debug:%d\n", *debug);
		pr_info("sdcardfs : options - uid:%d\n",
							opts->fs_low_uid);
		pr_info("sdcardfs : options - gid:%d\n",
							opts->fs_low_gid);
	}

	return 0;
}

int parse_options_remount(struct super_block *sb, char *options, int silent,
				struct sdcardfs_vfsmount_options *vfsopts)
{
	char *p;
	substring_t args[MAX_OPT_ARGS];
	int option;
	int debug;

	if (!options)
		return 0;

	while ((p = strsep(&options, ",")) != NULL) {
		int token;

		if (!*p)
			continue;

		token = match_token(p, sdcardfs_tokens, args);

		switch (token) {
		case Opt_debug:
			debug = 1;
			break;
		case Opt_gid:
			if (match_int(&args[0], &option))
				return 0;
			vfsopts->gid = option;

			break;
		case Opt_mask:
			if (match_int(&args[0], &option))
				return 0;
			vfsopts->mask = option;
			break;
		case Opt_multiuser:
		case Opt_userid:
		case Opt_fsuid:
		case Opt_fsgid:
		case Opt_reserved_mb:
			pr_warn("Option \"%s\" can't be changed during remount\n", p);
			break;
		/* unknown option */
		default:
			if (!silent)
				pr_err("Unrecognized mount option \"%s\" or missing value", p);
			return -EINVAL;
		}
	}

	if (debug) {
		pr_info("sdcardfs : options - debug:%d\n", debug);
		pr_info("sdcardfs : options - gid:%d\n", vfsopts->gid);
		pr_info("sdcardfs : options - mask:%d\n", vfsopts->mask);
	}

	return 0;
}

#if 0
/*
 * our custom d_alloc_root work-alike
 *
 * we can't use d_alloc_root if we want to use our own interpose function
 * unchanged, so we simply call our own "fake" d_alloc_root
 */
static struct dentry *sdcardfs_d_alloc_root(struct super_block *sb)
{
	struct dentry *ret = NULL;

	if (sb) {
		static const struct qstr name = {
			.name = "/",
			.len = 1
		};

		ret = __d_alloc(sb, &name);
		if (ret) {
			d_set_d_op(ret, &sdcardfs_ci_dops);
			ret->d_parent = ret;
		}
	}
	return ret;
}
#endif

DEFINE_MUTEX(sdcardfs_super_list_lock);
EXPORT_SYMBOL_GPL(sdcardfs_super_list_lock);
LIST_HEAD(sdcardfs_super_list);
EXPORT_SYMBOL_GPL(sdcardfs_super_list);

/*
 * There is no need to lock the sdcardfs_super_info's rwsem as there is no
 * way anyone can have a reference to the superblock at this point in time.
 */
static int sdcardfs_read_super(struct vfsmount *mnt, struct super_block *sb,
		const char *dev_name, void *raw_data, int silent)
{
	int err = 0;
	int debug;
	struct super_block *lower_sb;
	struct path lower_path;
	struct sdcardfs_sb_info *sb_info;
	struct sdcardfs_vfsmount_options *mnt_opt = mnt->data;
	struct inode *inode;

	pr_info("sdcardfs version 2.0\n");

	if (!dev_name) {
		pr_err("sdcardfs: read_super: missing dev_name argument\n");
		err = -EINVAL;
		goto out;
	}

	pr_info("sdcardfs: dev_name -> %s\n", dev_name);
	pr_info("sdcardfs: options -> %s\n", (char *)raw_data);
	pr_info("sdcardfs: mnt -> %p\n", mnt);

	/* parse lower path */
	err = kern_path(dev_name, LOOKUP_FOLLOW | LOOKUP_DIRECTORY,
			&lower_path);
	if (err) {
		pr_err("sdcardfs: error accessing lower directory '%s'\n", dev_name);
		goto out;
	}

	/* allocate superblock private data */
	sb->s_fs_info = kzalloc(sizeof(struct sdcardfs_sb_info), GFP_KERNEL);
	if (!SDCARDFS_SB(sb)) {
		pr_crit("sdcardfs: read_super: out of memory\n");
		err = -ENOMEM;
		goto out_free;
	}

	sb_info = sb->s_fs_info;

	/* parse options */
	err = parse_options(sb, raw_data, silent, &debug, mnt_opt, &sb_info->options);
	if (err) {
		pr_err("sdcardfs: invalid options\n");
		goto out_freesbi;
	}

	pkgl_id = packagelist_create((char *)dev_name, sb);
	if(IS_ERR(pkgl_id)) {
		err = -ENOMEM;
		printk(KERN_ERR	"sdcardfs: packagelist create fail\n");
		goto out_freesbi;
	}
	else
		sb_info->pkgl_id = pkgl_id;

	/* set the lower superblock field of upper superblock */
	lower_sb = lower_path.dentry->d_sb;
	atomic_inc(&lower_sb->s_active);
	sdcardfs_set_lower_super(sb, lower_sb);

	/* inherit maxbytes from lower file system */
	sb->s_maxbytes = lower_sb->s_maxbytes;

	/*
	 * Our c/m/atime granularity is 1 ns because we may stack on file
	 * systems whose granularity is as good.
	 */
	sb->s_time_gran = 1;

	sb->s_magic = SDCARDFS_SUPER_MAGIC;
	sb->s_op = &sdcardfs_sops;

	/* see comment next to the definition of sdcardfs_d_alloc_root */
	sb->s_root = sdcardfs_d_alloc_root(sb);
	if (!sb->s_root) {
		err = -ENOMEM;
		goto out_sput;
	}

	/* link the upper and lower dentries */
	sb->s_root->d_fsdata = NULL;
	err = new_dentry_private_data(sb->s_root);
	if (err)
		goto out_freeroot;

	/* set the lower dentries for s_root */
	sdcardfs_set_lower_path(sb->s_root, &lower_path);

	/* call interpose to create the upper level inode */
	err = sdcardfs_interpose(sb->s_root, sb, &lower_path);
	if (!err) {
		/* setup permission policy */
		if (sb_info->options.multi_user){
			setup_derived_state_for_multiuser_gid(sb->s_root->d_inode,
					PERM_PRE_ROOT, 0, AID_ROOT, multiuser_get_uid(0,sb_info->options.sdfs_gid), false);
			sb_info->obbpath_s = kzalloc(PATH_MAX, GFP_KERNEL);
#ifdef CONFIG_MACH_LGE
			if(sb_info->obbpath_s)
				snprintf(sb_info->obbpath_s, PATH_MAX, "%s/obb", dev_name);
			else
				printk(KERN_INFO "sdcardfs: kzalloc fail 1\n");
#else
			snprintf(sb_info->obbpath_s, PATH_MAX, "%s/obb", dev_name);
#endif
		} else {
			setup_derived_state(sb->s_root->d_inode,
					PERM_ROOT, sb_info->options.userid, AID_ROOT, sb_info->options.sdfs_gid, false);
			sb_info->obbpath_s = kzalloc(PATH_MAX, GFP_KERNEL);
#ifdef CONFIG_MACH_LGE
			if(sb_info->obbpath_s)
				snprintf(sb_info->obbpath_s, PATH_MAX, "%s/Android/obb", dev_name);
			else
				printk(KERN_INFO "sdcardfs: kzalloc fail 2\n");
#else
			snprintf(sb_info->obbpath_s, PATH_MAX, "%s/Android/obb", dev_name);
#endif
		}
		fix_derived_permission(sb->s_root->d_inode, sb_info->options.sdfs_mask);

		sb_info->devpath = kzalloc(PATH_MAX, GFP_KERNEL);
		if(sb_info->devpath && dev_name)
			strncpy(sb_info->devpath, dev_name, strlen(dev_name));

		if (!silent)
			printk(KERN_INFO "sdcardfs: mounted on top of %s type %s\n",
					dev_name, lower_sb->s_type->name);
		goto out;
	}
	/* else error: fall through */

	free_dentry_private_data(sb->s_root);
out_freeroot:
	dput(sb->s_root);
out_sput:
	/* drop refs we took earlier */
	atomic_dec(&lower_sb->s_active);
	packagelist_destroy(sb_info->pkgl_id,((struct sdcardfs_sb_info *)sb->s_fs_info)->options.type);
out_freesbi:
	kfree(SDCARDFS_SB(sb));
	sb->s_fs_info = NULL;
out_free:
	path_put(&lower_path);

out:
	return err;
}

struct sdcardfs_mount_private {
	struct vfsmount *mnt;
	const char *dev_name;
	void *raw_data;
};

static int __sdcardfs_fill_super(
	struct super_block *sb,
	void *_priv, int silent)
{
	struct sdcardfs_mount_private *priv = _priv;

	return sdcardfs_read_super(priv->mnt,
		sb, priv->dev_name, priv->raw_data, silent);
}

static struct dentry *sdcardfs_mount(struct vfsmount *mnt,
		struct file_system_type *fs_type, int flags,
			    const char *dev_name, void *raw_data)
{
	struct sdcardfs_mount_private priv = {
		.mnt = mnt,
		.dev_name = dev_name,
		.raw_data = raw_data
	};

	return mount_nodev(fs_type, flags,
		&priv, __sdcardfs_fill_super);
}

static struct dentry *sdcardfs_mount_wrn(struct file_system_type *fs_type,
		    int flags, const char *dev_name, void *raw_data)
{
	WARN(1, "sdcardfs does not support mount. Use mount2.\n");
	return ERR_PTR(-EINVAL);
}

void *sdcardfs_alloc_mnt_data(void)
{
	return kmalloc(sizeof(struct sdcardfs_vfsmount_options), GFP_KERNEL);
}

void sdcardfs_kill_sb(struct super_block *sb)
{
	struct sdcardfs_sb_info *sbi;

	if (sb->s_magic == SDCARDFS_SUPER_MAGIC) {
		sbi = SDCARDFS_SB(sb);
		mutex_lock(&sdcardfs_super_list_lock);
		list_del(&sbi->list);
		mutex_unlock(&sdcardfs_super_list_lock);
	}
	kill_anon_super(sb);
}

static struct file_system_type sdcardfs_fs_type = {
	.owner		= THIS_MODULE,
	.name		= SDCARDFS_NAME,
	.mount		= sdcardfs_mount_wrn,
	.mount2		= sdcardfs_mount,
	.alloc_mnt_data = sdcardfs_alloc_mnt_data,
	.kill_sb	= sdcardfs_shutdown_super,
	.fs_flags	= 0,
};
MODULE_ALIAS_FS(SDCARDFS_NAME);

static int __init init_sdcardfs_fs(void)
{
	int err;

	pr_info("Registering sdcardfs %s\n", SDCARDFS_VERSION);

	err = sdcardfs_init_inode_cache();
	if (err)
		goto out;
	err = sdcardfs_init_dentry_cache();
	if (err)
		goto out;
	err = packagelist_init();
	if (err)
		goto out;
	err = register_filesystem(&sdcardfs_fs_type);
out:
	if (err) {
		sdcardfs_destroy_inode_cache();
		sdcardfs_destroy_dentry_cache();
		packagelist_exit();
	}
	return err;
}

static void __exit exit_sdcardfs_fs(void)
{
	sdcardfs_destroy_inode_cache();
	sdcardfs_destroy_dentry_cache();
	packagelist_exit();
	unregister_filesystem(&sdcardfs_fs_type);
	pr_info("Completed sdcardfs module unload\n");
}

/* Original wrapfs authors */
MODULE_AUTHOR("Erez Zadok, Filesystems and Storage Lab, Stony Brook University (http://www.fsl.cs.sunysb.edu/)");

/* Original sdcardfs authors */
MODULE_AUTHOR("Woojoong Lee, Daeho Jeong, Kitae Lee, Yeongjin Gil System Memory Lab., Samsung Electronics");

/* Current maintainer */
MODULE_AUTHOR("Daniel Rosenberg, Google");
MODULE_DESCRIPTION("Sdcardfs " SDCARDFS_VERSION);
MODULE_LICENSE("GPL");

module_init(init_sdcardfs_fs);
module_exit(exit_sdcardfs_fs);
