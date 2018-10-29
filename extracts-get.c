//[/source3/smbd/vfs.c]

NTSTATUS smb_vfs_call_fget_nt_acl(struct vfs_handle_struct *handle,		/* IN */
				  struct files_struct *fsp,			/* IN */
				  uint32_t security_info,			/* IN */
				  TALLOC_CTX *mem_ctx,				/* ? */
				  struct security_descriptor **ppdesc)		/* OUT */
{
	VFS_FIND(fget_nt_acl);
	return handle->fns->fget_nt_acl_fn(handle, fsp, security_info,
					   mem_ctx, ppdesc);
//_____________________________________________________________________________________________
//[/source3/modules/vfs_zfsacl.c]
static NTSTATUS zfsacl_fget_nt_acl(struct vfs_handle_struct *handle,		/* IN */
				   struct files_struct *fsp,			/* IN */
				   uint32_t security_info,			/* IN */
				   TALLOC_CTX *mem_ctx,				/* ? */
				   struct security_descriptor **ppdesc)		/* OUT */
{
	struct SMB4ACL_T *pacl;
	NTSTATUS status;
	TALLOC_CTX *frame = talloc_stackframe();

	status = zfs_get_nt_acl_common(handle->conn, frame,
				       fsp->fsp_name, &pacl);
//_____________________________________________________________________________________________
static NTSTATUS zfs_get_nt_acl_common(struct connection_struct *conn,		/* IN */
				      TALLOC_CTX *mem_ctx,			/* ? */
				      const struct smb_filename *smb_fname,	/* IN */
				      struct SMB4ACL_T **ppacl)			/* OUT */
{
	int naces, i;
	ace_t *acebuf;
	struct SMB4ACL_T *pacl;
	SMB_STRUCT_STAT sbuf;
	const SMB_STRUCT_STAT *psbuf = NULL;
	int ret;
	bool is_dir;

	if (VALID_STAT(smb_fname->st)) {
		psbuf = &smb_fname->st;
	}

	if (psbuf == NULL) {
		ret = vfs_stat_smb_basename(conn, smb_fname, &sbuf);
		if (ret != 0) {
			DBG_INFO("stat [%s]failed: %s\n",
				 smb_fname_str_dbg(smb_fname), strerror(errno));
			return map_nt_error_from_unix(errno);
		}
		psbuf = &sbuf;
	}
	is_dir = S_ISDIR(psbuf->st_ex_mode);

	/* read the number of file aces */
	if((naces = acl(smb_fname->base_name, ACE_GETACLCNT, 0, NULL)) == -1) {
		if(errno == ENOSYS) {
			DEBUG(9, ("acl(ACE_GETACLCNT, %s): Operation is not "
				  "supported on the filesystem where the file "
				  "reside\n", smb_fname->base_name));
		} else {
			DEBUG(9, ("acl(ACE_GETACLCNT, %s): %s ", smb_fname->base_name,
					strerror(errno)));
		}
		return map_nt_error_from_unix(errno);
	}
	/* allocate the field of ZFS aces */
	mem_ctx = talloc_tos();
	acebuf = (ace_t *) talloc_size(mem_ctx, sizeof(ace_t)*naces);
	if(acebuf == NULL) {
		return NT_STATUS_NO_MEMORY;
	}
	/* read the aces into the field */
	if(acl(smb_fname->base_name, ACE_GETACL, naces, acebuf) < 0) {
		DEBUG(9, ("acl(ACE_GETACL, %s): %s ", smb_fname->base_name,
				strerror(errno)));
		return map_nt_error_from_unix(errno);
	}
	/* create SMB4ACL data */
	if((pacl = smb_create_smb4acl(mem_ctx)) == NULL) {
		return NT_STATUS_NO_MEMORY;
	}
	for(i=0; i<naces; i++) {
		SMB_ACE4PROP_T aceprop;

		aceprop.aceType  = (uint32_t) acebuf[i].a_type;
		aceprop.aceFlags = (uint32_t) acebuf[i].a_flags;
		aceprop.aceMask  = (uint32_t) acebuf[i].a_access_mask;
		aceprop.who.id   = (uint32_t) acebuf[i].a_who;

		/*
		 * Windows clients expect SYNC on acls to correctly allow
		 * rename, cf bug #7909. But not on DENY ace entries, cf bug
		 * #8442.
		 */
		if (aceprop.aceType == SMB_ACE4_ACCESS_ALLOWED_ACE_TYPE) {
			aceprop.aceMask |= SMB_ACE4_SYNCHRONIZE;
		}

		if (is_dir && (aceprop.aceMask & SMB_ACE4_ADD_FILE)) {
			aceprop.aceMask |= SMB_ACE4_DELETE_CHILD;
		}

		if(aceprop.aceFlags & ACE_OWNER) {
			aceprop.flags = SMB_ACE4_ID_SPECIAL;
			aceprop.who.special_id = SMB_ACE4_WHO_OWNER;
		} else if(aceprop.aceFlags & ACE_GROUP) {
			aceprop.flags = SMB_ACE4_ID_SPECIAL;
			aceprop.who.special_id = SMB_ACE4_WHO_GROUP;
		} else if(aceprop.aceFlags & ACE_EVERYONE) {
			aceprop.flags = SMB_ACE4_ID_SPECIAL;
			aceprop.who.special_id = SMB_ACE4_WHO_EVERYONE;
		} else {
			aceprop.flags	= 0;
		}
		if(smb_add_ace4(pacl, &aceprop) == NULL)
			return NT_STATUS_NO_MEMORY;
	}

	*ppacl = pacl;
	return NT_STATUS_OK;
}
//_____________________________________________________________________________________________
	if (!NT_STATUS_IS_OK(status)) {
		TALLOC_FREE(frame);
		return status;
	}

	status = smb_fget_nt_acl_nfs4(fsp, NULL, security_info, mem_ctx,
				      ppdesc, pacl);
//_____________________________________________________________________________________________
//[/source3/modules/nfs4_acls.c]

NTSTATUS smb_fget_nt_acl_nfs4(files_struct *fsp,				/* IN */
			      const struct smbacl4_vfs_params *pparams,		/* - */
			      uint32_t security_info,				/* IN */
			      TALLOC_CTX *mem_ctx,				/* ? */
			      struct security_descriptor **ppdesc,		/* OUT */
			      struct SMB4ACL_T *theacl)				/* IN */
{
	SMB_STRUCT_STAT sbuf;
	struct smbacl4_vfs_params params;
	SMB_STRUCT_STAT *psbuf = NULL;

	DEBUG(10, ("smb_fget_nt_acl_nfs4 invoked for %s\n", fsp_str_dbg(fsp)));

	if (VALID_STAT(fsp->fsp_name->st)) {
		psbuf = &fsp->fsp_name->st;
	}

	if (psbuf == NULL) {
		if (smbacl4_fGetFileOwner(fsp, &sbuf)) {
			return map_nt_error_from_unix(errno);
		}
		psbuf = &sbuf;
	}

	if (pparams == NULL) {
		/* Special behaviours */
		if (smbacl4_get_vfs_params(fsp->conn, &params)) {
			return NT_STATUS_NO_MEMORY;
		}
		pparams = &params;
	}

	return smb_get_nt_acl_nfs4_common(psbuf, pparams, security_info,
					  mem_ctx, ppdesc, theacl);
//_____________________________________________________________________________________________
static NTSTATUS smb_get_nt_acl_nfs4_common(const SMB_STRUCT_STAT *sbuf,			/* IN */
					   const struct smbacl4_vfs_params *params,	/* IN */
					   uint32_t security_info,			/* IN */
					   TALLOC_CTX *mem_ctx,				/* ? */
					   struct security_descriptor **ppdesc,		/* OUT */
					   struct SMB4ACL_T *theacl)			/* IN */
{
	int good_aces = 0;
	struct dom_sid sid_owner, sid_group;
	size_t sd_size = 0;
	struct security_ace *nt_ace_list = NULL;
	struct security_acl *psa = NULL;
	TALLOC_CTX *frame = talloc_stackframe();
	bool ok;

	if (theacl==NULL) {
		TALLOC_FREE(frame);
		return NT_STATUS_ACCESS_DENIED; /* special because we
						 * need to think through
						 * the null case.*/
	}

	uid_to_sid(&sid_owner, sbuf->st_ex_uid);
	gid_to_sid(&sid_group, sbuf->st_ex_gid);

	ok = smbacl4_nfs42win(frame, params, theacl, &sid_owner, &sid_group,
			      S_ISDIR(sbuf->st_ex_mode),
			      &nt_ace_list, &good_aces);
//_____________________________________________________________________________________________
static bool smbacl4_nfs42win(TALLOC_CTX *mem_ctx,				/* IN */
	const struct smbacl4_vfs_params *params,				/* IN */
	struct SMB4ACL_T *acl, /* in */						/* IN */
	struct dom_sid *psid_owner, /* in */					/* IN */
	struct dom_sid *psid_group, /* in */					/* IN */
	bool is_directory, /* in */						/* IN */
	struct security_ace **ppnt_ace_list, /* out */				/* OUT */
	int *pgood_aces /* out */						/* OUT */
)
{
	struct SMB4ACE_T *aceint;
	struct security_ace *nt_ace_list = NULL;
	int good_aces = 0;

	DEBUG(10, ("%s entered\n", __func__));

	nt_ace_list = talloc_zero_array(mem_ctx, struct security_ace,
					2 * acl->naces);
	if (nt_ace_list==NULL)
	{
		DEBUG(10, ("talloc error with %d aces", acl->naces));
		errno = ENOMEM;
		return false;
	}

	for (aceint = acl->first; aceint != NULL; aceint = aceint->next) {
		uint32_t mask;
		struct dom_sid sid;
		SMB_ACE4PROP_T	*ace = &aceint->prop;
		uint32_t win_ace_flags;

		DEBUG(10, ("type: %d, iflags: %x, flags: %x, "
			   "mask: %x, who: %d\n",
			   ace->aceType, ace->flags,
			   ace->aceFlags, ace->aceMask, ace->who.id));

		if (ace->flags & SMB_ACE4_ID_SPECIAL) {
			switch (ace->who.special_id) {
			case SMB_ACE4_WHO_OWNER:
				sid_copy(&sid, psid_owner);
				break;
			case SMB_ACE4_WHO_GROUP:
				sid_copy(&sid, psid_group);
				break;
			case SMB_ACE4_WHO_EVERYONE:
				sid_copy(&sid, &global_sid_World);
				break;
			default:
				DEBUG(8, ("invalid special who id %d "
					"ignored\n", ace->who.special_id));
				continue;
			}
		} else {
			if (ace->aceFlags & SMB_ACE4_IDENTIFIER_GROUP) {
				gid_to_sid(&sid, ace->who.gid);
			} else {
				uid_to_sid(&sid, ace->who.uid);
			}
		}
		DEBUG(10, ("mapped %d to %s\n", ace->who.id,
			   sid_string_dbg(&sid)));

		if (!is_directory && params->map_full_control) {
			/*
			 * Do we have all access except DELETE_CHILD
			 * (not caring about the delete bit).
			 */
			uint32_t test_mask = ((ace->aceMask|SMB_ACE4_DELETE|SMB_ACE4_DELETE_CHILD) &
						SMB_ACE4_ALL_MASKS);
			if (test_mask == SMB_ACE4_ALL_MASKS) {
				ace->aceMask |= SMB_ACE4_DELETE_CHILD;
			}
		}

		win_ace_flags = map_nfs4_ace_flags_to_windows_ace_flags(
			ace->aceFlags);
		if (!is_directory &&
		    (win_ace_flags & (SEC_ACE_FLAG_OBJECT_INHERIT|
				      SEC_ACE_FLAG_CONTAINER_INHERIT))) {
			/*
			 * GPFS sets inherits dir_inhert and file_inherit flags
			 * to files, too, which confuses windows, and seems to
			 * be wrong anyways. ==> Map these bits away for files.
			 */
			DEBUG(10, ("removing inherit flags from nfs4 ace\n"));
			win_ace_flags &= ~(SEC_ACE_FLAG_OBJECT_INHERIT|
					   SEC_ACE_FLAG_CONTAINER_INHERIT);
		}
		DEBUG(10, ("Windows mapped ace flags: 0x%x => 0x%x\n",
		      ace->aceFlags, win_ace_flags));

		mask = ace->aceMask;

		/* Mapping of owner@ and group@ to creator owner and
		   creator group. Keep old behavior in mode special. */
		if (params->mode != e_special &&
		    ace->flags & SMB_ACE4_ID_SPECIAL &&
		    (ace->who.special_id == SMB_ACE4_WHO_OWNER ||
		     ace->who.special_id == SMB_ACE4_WHO_GROUP)) {
			DEBUG(10, ("Map special entry\n"));
			if (!(win_ace_flags & SEC_ACE_FLAG_INHERIT_ONLY)) {
				uint32_t win_ace_flags_current;
				DEBUG(10, ("Map current sid\n"));
				win_ace_flags_current = win_ace_flags &
					~(SEC_ACE_FLAG_OBJECT_INHERIT |
					  SEC_ACE_FLAG_CONTAINER_INHERIT);
				init_sec_ace(&nt_ace_list[good_aces++], &sid,
					     ace->aceType, mask,
					     win_ace_flags_current);
			}
			if (ace->who.special_id == SMB_ACE4_WHO_OWNER &&
			    win_ace_flags & (SEC_ACE_FLAG_OBJECT_INHERIT |
					     SEC_ACE_FLAG_CONTAINER_INHERIT)) {
				uint32_t win_ace_flags_creator;
				DEBUG(10, ("Map creator owner\n"));
				win_ace_flags_creator = win_ace_flags |
					SMB_ACE4_INHERIT_ONLY_ACE;
				init_sec_ace(&nt_ace_list[good_aces++],
					     &global_sid_Creator_Owner,
					     ace->aceType, mask,
					     win_ace_flags_creator);
			}
			if (ace->who.special_id == SMB_ACE4_WHO_GROUP &&
			    win_ace_flags & (SEC_ACE_FLAG_OBJECT_INHERIT |
					     SEC_ACE_FLAG_CONTAINER_INHERIT)) {
				uint32_t win_ace_flags_creator;
				DEBUG(10, ("Map creator owner group\n"));
				win_ace_flags_creator = win_ace_flags |
					SMB_ACE4_INHERIT_ONLY_ACE;
				init_sec_ace(&nt_ace_list[good_aces++],
					     &global_sid_Creator_Group,
					     ace->aceType, mask,
					     win_ace_flags_creator);
			}
		} else {
			DEBUG(10, ("Map normal sid\n"));
			init_sec_ace(&nt_ace_list[good_aces++], &sid,
				     ace->aceType, mask,
				     win_ace_flags);
		}
	}

	nt_ace_list = talloc_realloc(mem_ctx, nt_ace_list, struct security_ace,
				     good_aces);

	/* returns a NULL ace list when good_aces is zero. */
	if (good_aces && nt_ace_list == NULL) {
		DEBUG(10, ("realloc error with %d aces", good_aces));
		errno = ENOMEM;
		return false;
	}

	*ppnt_ace_list = nt_ace_list;
	*pgood_aces = good_aces;

	return true;
}
//_____________________________________________________________________________________________
	if (!ok) {
		DEBUG(8,("smbacl4_nfs42win failed\n"));
		TALLOC_FREE(frame);
		return map_nt_error_from_unix(errno);
	}

	psa = make_sec_acl(frame, NT4_ACL_REVISION, good_aces, nt_ace_list);
	if (psa == NULL) {
		DEBUG(2,("make_sec_acl failed\n"));
		TALLOC_FREE(frame);
		return NT_STATUS_NO_MEMORY;
	}

	DEBUG(10,("after make sec_acl\n"));
	*ppdesc = make_sec_desc(
		mem_ctx, SD_REVISION, smbacl4_get_controlflags(theacl),
		(security_info & SECINFO_OWNER) ? &sid_owner : NULL,
		(security_info & SECINFO_GROUP) ? &sid_group : NULL,
		NULL, psa, &sd_size);
	if (*ppdesc==NULL) {
		DEBUG(2,("make_sec_desc failed\n"));
		TALLOC_FREE(frame);
		return NT_STATUS_NO_MEMORY;
	}

	DEBUG(10, ("smb_get_nt_acl_nfs4_common successfully exited with "
		   "sd_size %d\n",
		   (int)ndr_size_security_descriptor(*ppdesc, 0)));

	TALLOC_FREE(frame);
	return NT_STATUS_OK;
}
//_____________________________________________________________________________________________
}
//_____________________________________________________________________________________________
//[/source3/modules/vfs_zfsacl.c]

	TALLOC_FREE(frame);
	return status;
}


//_____________________________________________________________________________________________
//[/source3/smbd/vfs.c]

}
