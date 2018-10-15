//[/source3/smbd/vfs.c]

NTSTATUS smb_vfs_call_fset_nt_acl(struct vfs_handle_struct *handle,
				  struct files_struct *fsp,
				  uint32_t security_info_sent,
				  const struct security_descriptor *psd)
{
	VFS_FIND(fset_nt_acl);
	return handle->fns->fset_nt_acl_fn(handle, fsp, security_info_sent, 
					   psd);
//_____________________________________________________________________________
//[/source3/modules/vfs_zfsacl.c]

static NTSTATUS zfsacl_fset_nt_acl(vfs_handle_struct *handle,
			 files_struct *fsp,
			 uint32_t security_info_sent,
			 const struct security_descriptor *psd)
{
	return zfs_set_nt_acl(handle, fsp, security_info_sent, psd);
//_____________________________________________________________________________
static NTSTATUS zfs_set_nt_acl(vfs_handle_struct *handle, files_struct *fsp,
			   uint32_t security_info_sent,
			   const struct security_descriptor *psd)
{
        return smb_set_nt_acl_nfs4(handle, fsp, NULL, security_info_sent, psd,
				   zfs_process_smbacl);
//_____________________________________________________________________________
//[/source3/modules/nfs4_acls.c]

NTSTATUS smb_set_nt_acl_nfs4(vfs_handle_struct *handle, files_struct *fsp,
	const struct smbacl4_vfs_params *pparams,
	uint32_t security_info_sent,
	const struct security_descriptor *psd,
	set_nfs4acl_native_fn_t set_nfs4_native)
{
	struct smbacl4_vfs_params params;
	struct SMB4ACL_T *theacl = NULL;
	bool	result;

	SMB_STRUCT_STAT sbuf;
	bool set_acl_as_root = false;
	uid_t newUID = (uid_t)-1;
	gid_t newGID = (gid_t)-1;
	int saved_errno;
	TALLOC_CTX *frame = talloc_stackframe();

	DEBUG(10, ("smb_set_nt_acl_nfs4 invoked for %s\n", fsp_str_dbg(fsp)));

	if ((security_info_sent & (SECINFO_DACL |
		SECINFO_GROUP | SECINFO_OWNER)) == 0)
	{
		DEBUG(9, ("security_info_sent (0x%x) ignored\n",
			security_info_sent));
		TALLOC_FREE(frame);
		return NT_STATUS_OK; /* won't show error - later to be
				      * refined... */
	}

	if (pparams == NULL) {
		/* Special behaviours */
		if (smbacl4_get_vfs_params(fsp->conn, &params)) {
			TALLOC_FREE(frame);
			return NT_STATUS_NO_MEMORY;
		}
		pparams = &params;
	}

	if (smbacl4_fGetFileOwner(fsp, &sbuf)) {
		TALLOC_FREE(frame);
		return map_nt_error_from_unix(errno);
	}

	if (pparams->do_chown) {
		/* chown logic is a copy/paste from posix_acl.c:set_nt_acl */
		NTSTATUS status = unpack_nt_owners(fsp->conn, &newUID, &newGID,
						   security_info_sent, psd);
		if (!NT_STATUS_IS_OK(status)) {
			DEBUG(8, ("unpack_nt_owners failed"));
			TALLOC_FREE(frame);
			return status;
		}
		if (((newUID != (uid_t)-1) && (sbuf.st_ex_uid != newUID)) ||
		    ((newGID != (gid_t)-1) && (sbuf.st_ex_gid != newGID))) {

			status = try_chown(fsp, newUID, newGID);
			if (!NT_STATUS_IS_OK(status)) {
				DEBUG(3,("chown %s, %u, %u failed. Error = "
					 "%s.\n", fsp_str_dbg(fsp),
					 (unsigned int)newUID,
					 (unsigned int)newGID,
					 nt_errstr(status)));
				TALLOC_FREE(frame);
				return status;
			}

			DEBUG(10,("chown %s, %u, %u succeeded.\n",
				  fsp_str_dbg(fsp), (unsigned int)newUID,
				  (unsigned int)newGID));
			if (smbacl4_GetFileOwner(fsp->conn,
						 fsp->fsp_name,
						 &sbuf)){
				TALLOC_FREE(frame);
				return map_nt_error_from_unix(errno);
			}

			/* If we successfully chowned, we know we must
			 * be able to set the acl, so do it as root.
			 */
			set_acl_as_root = true;
		}
	}

	if (!(security_info_sent & SECINFO_DACL) || psd->dacl ==NULL) {
		DEBUG(10, ("no dacl found; security_info_sent = 0x%x\n",
			   security_info_sent));
		TALLOC_FREE(frame);
		return NT_STATUS_OK;
	}

	theacl = smbacl4_win2nfs4(frame, fsp, psd->dacl, pparams,
				  sbuf.st_ex_uid, sbuf.st_ex_gid);
//_____________________________________________________________________________
static struct SMB4ACL_T *smbacl4_win2nfs4(
	TALLOC_CTX *mem_ctx,
	const files_struct *fsp,
	const struct security_acl *dacl,
	const struct smbacl4_vfs_params *pparams,
	uid_t ownerUID,
	gid_t ownerGID
)
{
	struct SMB4ACL_T *theacl;
	uint32_t i;
	const char *filename = fsp->fsp_name->base_name;

	DEBUG(10, ("smbacl4_win2nfs4 invoked\n"));

	theacl = smb_create_smb4acl(mem_ctx);
//_____________________________________________________________________________
struct SMB4ACL_T *smb_create_smb4acl(TALLOC_CTX *mem_ctx)
{
	struct SMB4ACL_T *theacl;

	theacl = talloc_zero(mem_ctx, struct SMB4ACL_T);
	if (theacl==NULL)
	{
		DEBUG(0, ("TALLOC_SIZE failed\n"));
		errno = ENOMEM;
		return NULL;
	}
	theacl->controlflags = SEC_DESC_SELF_RELATIVE;
	/* theacl->first, last = NULL not needed */
	return theacl;
}
//_____________________________________________________________________________
	if (theacl==NULL)
		return NULL;

	for(i=0; i<dacl->num_aces; i++) {
		SMB_ACE4PROP_T	ace_v4;
		bool	addNewACE = true;

		if (!smbacl4_fill_ace4(fsp->fsp_name, pparams,
				       ownerUID, ownerGID,
				       dacl->aces + i, &ace_v4)) {
			DEBUG(3, ("Could not fill ace for file %s, SID %s\n",
				  filename,
				  sid_string_dbg(&((dacl->aces+i)->trustee))));
			continue;
		}
//_____________________________________________________________________________
static bool smbacl4_fill_ace4(
	const struct smb_filename *filename,
	const struct smbacl4_vfs_params *params,
	uid_t ownerUID,
	gid_t ownerGID,
	const struct security_ace *ace_nt, /* input */
	SMB_ACE4PROP_T *ace_v4 /* output */
)
{
	DEBUG(10, ("got ace for %s\n", sid_string_dbg(&ace_nt->trustee)));

	ZERO_STRUCTP(ace_v4);

	/* only ACCESS|DENY supported right now */
	ace_v4->aceType = ace_nt->type;

	ace_v4->aceFlags = map_windows_ace_flags_to_nfs4_ace_flags(
		ace_nt->flags);
//_____________________________________________________________________________
static uint32_t map_windows_ace_flags_to_nfs4_ace_flags(uint32_t win_ace_flags)
{
	uint32_t nfs4_ace_flags = 0;

	/* The windows flags <= 0xf map perfectly. */
	nfs4_ace_flags = win_ace_flags & (SMB_ACE4_FILE_INHERIT_ACE|
				      SMB_ACE4_DIRECTORY_INHERIT_ACE|
				      SMB_ACE4_NO_PROPAGATE_INHERIT_ACE|
				      SMB_ACE4_INHERIT_ONLY_ACE);

	/* flags greater than 0xf have diverged :-(. */
	/* See the nfs4 ace flag definitions here:
	   http://www.ietf.org/rfc/rfc3530.txt.
	   And the Windows ace flag definitions here:
	   librpc/idl/security.idl. */
	if (win_ace_flags & SEC_ACE_FLAG_INHERITED_ACE) {
		nfs4_ace_flags |= SMB_ACE4_INHERITED_ACE;
	}

	return nfs4_ace_flags;
}
//_____________________________________________________________________________

	/* remove inheritance flags on files */
	if (VALID_STAT(filename->st) &&
	    !S_ISDIR(filename->st.st_ex_mode)) {
		DEBUG(10, ("Removing inheritance flags from a file\n"));
		ace_v4->aceFlags &= ~(SMB_ACE4_FILE_INHERIT_ACE|
				      SMB_ACE4_DIRECTORY_INHERIT_ACE|
				      SMB_ACE4_NO_PROPAGATE_INHERIT_ACE|
				      SMB_ACE4_INHERIT_ONLY_ACE);
	}

	ace_v4->aceMask = ace_nt->access_mask &
		(SEC_STD_ALL | SEC_FILE_ALL);

	se_map_generic(&ace_v4->aceMask, &file_generic_mapping);

	if (ace_v4->aceFlags!=ace_nt->flags)
		DEBUG(9, ("ace_v4->aceFlags(0x%x)!=ace_nt->flags(0x%x)\n",
			ace_v4->aceFlags, ace_nt->flags));

	if (ace_v4->aceMask!=ace_nt->access_mask)
		DEBUG(9, ("ace_v4->aceMask(0x%x)!=ace_nt->access_mask(0x%x)\n",
			ace_v4->aceMask, ace_nt->access_mask));

	if (dom_sid_equal(&ace_nt->trustee, &global_sid_World)) {
		ace_v4->who.special_id = SMB_ACE4_WHO_EVERYONE;
		ace_v4->flags |= SMB_ACE4_ID_SPECIAL;
	} else if (params->mode!=e_special &&
		   dom_sid_equal(&ace_nt->trustee,
				 &global_sid_Creator_Owner)) {
		DEBUG(10, ("Map creator owner\n"));
		ace_v4->who.special_id = SMB_ACE4_WHO_OWNER;
		ace_v4->flags |= SMB_ACE4_ID_SPECIAL;
		/* A non inheriting creator owner entry has no effect. */
		ace_v4->aceFlags |= SMB_ACE4_INHERIT_ONLY_ACE;
		if (!(ace_v4->aceFlags & SMB_ACE4_DIRECTORY_INHERIT_ACE)
		    && !(ace_v4->aceFlags & SMB_ACE4_FILE_INHERIT_ACE)) {
			return false;
		}
	} else if (params->mode!=e_special &&
		   dom_sid_equal(&ace_nt->trustee,
				 &global_sid_Creator_Group)) {
		DEBUG(10, ("Map creator owner group\n"));
		ace_v4->who.special_id = SMB_ACE4_WHO_GROUP;
		ace_v4->flags |= SMB_ACE4_ID_SPECIAL;
		/* A non inheriting creator group entry has no effect. */
		ace_v4->aceFlags |= SMB_ACE4_INHERIT_ONLY_ACE;
		if (!(ace_v4->aceFlags & SMB_ACE4_DIRECTORY_INHERIT_ACE)
		    && !(ace_v4->aceFlags & SMB_ACE4_FILE_INHERIT_ACE)) {
			return false;
		}
	} else {
		uid_t uid;
		gid_t gid;

		/*
		 * ID_TYPE_BOTH returns both uid and gid. Explicitly
		 * check for ownerUID to allow the mapping of the
		 * owner to a special entry in this idmap config.
		 */
		if (sid_to_uid(&ace_nt->trustee, &uid) && uid == ownerUID) {
			ace_v4->who.uid = uid;
		} else if (sid_to_gid(&ace_nt->trustee, &gid)) {
			ace_v4->aceFlags |= SMB_ACE4_IDENTIFIER_GROUP;
			ace_v4->who.gid = gid;
		} else if (sid_to_uid(&ace_nt->trustee, &uid)) {
			ace_v4->who.uid = uid;
		} else if (dom_sid_compare_domain(&ace_nt->trustee,
						  &global_sid_Unix_NFS) == 0) {
			return false;
		} else {
			DEBUG(1, ("nfs4_acls.c: file [%s]: could not "
				  "convert %s to uid or gid\n",
				  filename->base_name,
				  sid_string_dbg(&ace_nt->trustee)));
			return false;
		}
	}

	return true; /* OK */
}
//_____________________________________________________________________________

		if (pparams->acedup!=e_dontcare) {
			if (smbacl4_MergeIgnoreReject(pparams->acedup, theacl,
				&ace_v4, &addNewACE, i))
				return NULL;
//_____________________________________________________________________________
static int smbacl4_MergeIgnoreReject(
	enum smbacl4_acedup_enum acedup,
	struct SMB4ACL_T *theacl, /* may modify it */
	SMB_ACE4PROP_T *ace, /* the "new" ACE */
	bool	*paddNewACE,
	int	i
)
{
	int	result = 0;
	SMB_ACE4PROP_T *ace4found = smbacl4_find_equal_special(theacl, ace);
//_____________________________________________________________________________
static SMB_ACE4PROP_T *smbacl4_find_equal_special(
	struct SMB4ACL_T *acl,
	SMB_ACE4PROP_T *aceNew)
{
	struct SMB4ACE_T *aceint;

	for (aceint = acl->first; aceint != NULL; aceint = aceint->next) {
		SMB_ACE4PROP_T *ace = &aceint->prop;

		DEBUG(10,("ace type:0x%x flags:0x%x aceFlags:0x%x "
			  "new type:0x%x flags:0x%x aceFlags:0x%x\n",
			  ace->aceType, ace->flags, ace->aceFlags,
			  aceNew->aceType, aceNew->flags,aceNew->aceFlags));

		if (ace->flags == aceNew->flags &&
			ace->aceType==aceNew->aceType &&
			ace->aceFlags==aceNew->aceFlags)
		{
			/* keep type safety; e.g. gid is an u.short */
			if (ace->flags & SMB_ACE4_ID_SPECIAL)
			{
				if (ace->who.special_id ==
				    aceNew->who.special_id)
					return ace;
			} else {
				if (ace->aceFlags & SMB_ACE4_IDENTIFIER_GROUP)
				{
					if (ace->who.gid==aceNew->who.gid)
						return ace;
				} else {
					if (ace->who.uid==aceNew->who.uid)
						return ace;
				}
			}
		}
	}

	return NULL;
}
//_____________________________________________________________________________
	if (ace4found)
	{
		switch(acedup)
		{
		case e_merge: /* "merge" flags */
			*paddNewACE = false;
			ace4found->aceFlags |= ace->aceFlags;
			ace4found->aceMask |= ace->aceMask;
			break;
		case e_ignore: /* leave out this record */
			*paddNewACE = false;
			break;
		case e_reject: /* do an error */
			DEBUG(8, ("ACL rejected by duplicate nt ace#%d\n", i));
			errno = EINVAL; /* SHOULD be set on any _real_ error */
			result = -1;
			break;
		default:
			break;
		}
	}
	return result;
}
//_____________________________________________________________________________
		}

		if (addNewACE)
			smb_add_ace4(theacl, &ace_v4);
//_____________________________________________________________________________
struct SMB4ACE_T *smb_add_ace4(struct SMB4ACL_T *acl, SMB_ACE4PROP_T *prop)
{
	struct SMB4ACE_T *ace;

	ace = talloc_zero(acl, struct SMB4ACE_T);
	if (ace==NULL)
	{
		DBG_ERR("talloc_zero failed\n");
		errno = ENOMEM;
		return NULL;
	}
	ace->prop = *prop;

	if (acl->first==NULL)
	{
		acl->first = ace;
		acl->last = ace;
	} else {
		acl->last->next = ace;
		acl->last = ace;
	}
	acl->naces++;

	return ace;
}
//_____________________________________________________________________________
	}

	if (pparams->mode==e_simple) {
		smbacl4_substitute_simple(theacl, ownerUID, ownerGID);
//_____________________________________________________________________________
static int smbacl4_substitute_simple(
	struct SMB4ACL_T *acl,
	uid_t ownerUID,
	gid_t ownerGID
)
{
	struct SMB4ACE_T *aceint;

	for (aceint = acl->first; aceint != NULL; aceint = aceint->next) {
		SMB_ACE4PROP_T *ace = &aceint->prop;

		DEBUG(10,("ace type: %d, iflags: %x, flags: %x, "
			  "mask: %x, who: %d\n",
			  ace->aceType, ace->flags, ace->aceFlags,
			  ace->aceMask, ace->who.id));

		if (!(ace->flags & SMB_ACE4_ID_SPECIAL) &&
		    !(ace->aceFlags & SMB_ACE4_IDENTIFIER_GROUP) &&
		    ace->who.uid == ownerUID &&
		    !(ace->aceFlags & SMB_ACE4_INHERIT_ONLY_ACE) &&
		    !(ace->aceFlags & SMB_ACE4_FILE_INHERIT_ACE) &&
		    !(ace->aceFlags & SMB_ACE4_DIRECTORY_INHERIT_ACE)) {
			ace->flags |= SMB_ACE4_ID_SPECIAL;
			ace->who.special_id = SMB_ACE4_WHO_OWNER;
			DEBUG(10,("replaced with special owner ace\n"));
		}

		if (!(ace->flags & SMB_ACE4_ID_SPECIAL) &&
		    ace->aceFlags & SMB_ACE4_IDENTIFIER_GROUP &&
		    ace->who.uid == ownerGID &&
		    !(ace->aceFlags & SMB_ACE4_INHERIT_ONLY_ACE) &&
		    !(ace->aceFlags & SMB_ACE4_FILE_INHERIT_ACE) &&
		    !(ace->aceFlags & SMB_ACE4_DIRECTORY_INHERIT_ACE)) {
			ace->flags |= SMB_ACE4_ID_SPECIAL;
			ace->who.special_id = SMB_ACE4_WHO_GROUP;
			DEBUG(10,("replaced with special group ace\n"));
		}
	}
	return true; /* OK */
}
//_____________________________________________________________________________
	}

	if (pparams->mode==e_special) {
		smbacl4_substitute_special(theacl, ownerUID, ownerGID);
//_____________________________________________________________________________
static int smbacl4_substitute_special(
	struct SMB4ACL_T *acl,
	uid_t ownerUID,
	gid_t ownerGID
)
{
	struct SMB4ACE_T *aceint;

	for (aceint = acl->first; aceint != NULL; aceint = aceint->next) {
		SMB_ACE4PROP_T *ace = &aceint->prop;

		DEBUG(10,("ace type: %d, iflags: %x, flags: %x, "
			  "mask: %x, who: %d\n",
			  ace->aceType, ace->flags, ace->aceFlags,
			  ace->aceMask, ace->who.id));

		if (!(ace->flags & SMB_ACE4_ID_SPECIAL) &&
		    !(ace->aceFlags & SMB_ACE4_IDENTIFIER_GROUP) &&
		    ace->who.uid == ownerUID) {
			ace->flags |= SMB_ACE4_ID_SPECIAL;
			ace->who.special_id = SMB_ACE4_WHO_OWNER;
			DEBUG(10,("replaced with special owner ace\n"));
		}

		if (!(ace->flags & SMB_ACE4_ID_SPECIAL) &&
		    ace->aceFlags & SMB_ACE4_IDENTIFIER_GROUP &&
		    ace->who.uid == ownerGID) {
			ace->flags |= SMB_ACE4_ID_SPECIAL;
			ace->who.special_id = SMB_ACE4_WHO_GROUP;
			DEBUG(10,("replaced with special group ace\n"));
		}
	}
	return true; /* OK */
}
//_____________________________________________________________________________
	}

	return theacl;
}
//_____________________________________________________________________________
	if (!theacl) {
		TALLOC_FREE(frame);
		return map_nt_error_from_unix(errno);
	}

	smbacl4_set_controlflags(theacl, psd->type);
//_____________________________________________________________________________
bool smbacl4_set_controlflags(struct SMB4ACL_T *acl, uint16_t controlflags)
{
	if (acl == NULL) {
		return false;
	}

	acl->controlflags = controlflags;
	return true;
}
//_____________________________________________________________________________
	smbacl4_dump_nfs4acl(10, theacl);

	if (set_acl_as_root) {
		become_root();
	}
	result = set_nfs4_native(handle, fsp, theacl);
//_____________________________________________________________________________
//[/source3/smbd/vfs.c]

static bool zfs_process_smbacl(vfs_handle_struct *handle, files_struct *fsp,
			       struct SMB4ACL_T *smbacl)
{
	int naces = smb_get_naces(smbacl), i;
//_____________________________________________________________________________
//[/source3/modules/nfs4_acls.c]

uint32_t smb_get_naces(struct SMB4ACL_T *acl)
{
	if (acl == NULL) {
		return 0;
	}

	return acl->naces;
}
//_____________________________________________________________________________
//[/source3/smbd/vfs.c]

	ace_t *acebuf;
	struct SMB4ACE_T *smbace;
	TALLOC_CTX	*mem_ctx;
	bool have_special_id = false;

	/* allocate the field of ZFS aces */
	mem_ctx = talloc_tos();
	acebuf = (ace_t *) talloc_size(mem_ctx, sizeof(ace_t)*naces);
	if(acebuf == NULL) {
		errno = ENOMEM;
		return False;
	}
	/* handle all aces */
	for(smbace = smb_first_ace4(smbacl), i = 0;
			smbace!=NULL;
			smbace = smb_next_ace4(smbace), i++) {
		SMB_ACE4PROP_T *aceprop = smb_get_ace4(smbace);
//_____________________________________________________________________________
//[/source3/modules/nfs4_acls.c]

SMB_ACE4PROP_T *smb_get_ace4(struct SMB4ACE_T *ace)
{
	if (ace == NULL) {
		return NULL;
	}

	return &ace->prop;
}
//_____________________________________________________________________________
//[/source3/smbd/vfs.c]


		acebuf[i].a_type        = aceprop->aceType;
		acebuf[i].a_flags       = aceprop->aceFlags;
		acebuf[i].a_access_mask = aceprop->aceMask;
		/* SYNC on acls is a no-op on ZFS.
		   See bug #7909. */
		acebuf[i].a_access_mask &= ~SMB_ACE4_SYNCHRONIZE;
		acebuf[i].a_who         = aceprop->who.id;
		if(aceprop->flags & SMB_ACE4_ID_SPECIAL) {
			switch(aceprop->who.special_id) {
			case SMB_ACE4_WHO_EVERYONE:
				acebuf[i].a_flags |= ACE_EVERYONE;
				break;
			case SMB_ACE4_WHO_OWNER:
				acebuf[i].a_flags |= ACE_OWNER;
				break;
			case SMB_ACE4_WHO_GROUP:
				acebuf[i].a_flags |= ACE_GROUP|ACE_IDENTIFIER_GROUP;
				break;
			default:
				DEBUG(8, ("unsupported special_id %d\n", \
					aceprop->who.special_id));
				continue; /* don't add it !!! */
			}
			have_special_id = true;
		}
	}

	if (!have_special_id
	    && lp_parm_bool(fsp->conn->params->service, "zfsacl",
			    "denymissingspecial", false)) {
		errno = EACCES;
		return false;
	}

	SMB_ASSERT(i == naces);

	/* store acl */
	if(acl(fsp->fsp_name->base_name, ACE_SETACL, naces, acebuf)) {
		if(errno == ENOSYS) {
			DEBUG(9, ("acl(ACE_SETACL, %s): Operation is not "
				  "supported on the filesystem where the file "
				  "reside", fsp_str_dbg(fsp)));
		} else {
			DEBUG(9, ("acl(ACE_SETACL, %s): %s ", fsp_str_dbg(fsp),
				  strerror(errno)));
		}
		return 0;
	}

	return True;
}
//_____________________________________________________________________________
//[/source3/modules/nfs4_acls.c]

	saved_errno = errno;
	if (set_acl_as_root) {
		unbecome_root();
	}

	TALLOC_FREE(frame);

	if (result!=true) {
		errno = saved_errno;
		DEBUG(10, ("set_nfs4_native failed with %s\n",
			   strerror(errno)));
		return map_nt_error_from_unix(errno);
	}

	DEBUG(10, ("smb_set_nt_acl_nfs4 succeeded\n"));
	return NT_STATUS_OK;
}
//_____________________________________________________________________________
}
//_____________________________________________________________________________
}
//_____________________________________________________________________________
//[/source3/smbd/vfs.c]

}

//_____________________________________________________________________________
