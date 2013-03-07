/*
 * ProFTPD: mod_trash
 * Copyright (c) 2009-2012 B.Bradley
 */

#include "conf.h"
#include "privs.h"

#define MOD_TRASH_VERSION		"mod_trash/0.1"

static int trashengine = FALSE;
static int usetrash = FALSE;


/*
Functions to walk path of deleted file and duplicate path structure under TrashDirectory
Almost entirely copied from mod_site_misc.c
Modified to copy mode-perms of source directory to new directory under TrashDirectory
*/
static int create_dir(const char *dir, mode_t mode) {
  struct stat st;
  int result;

  pr_fs_clear_cache();
  result = pr_fsio_stat(dir, &st);
  if (result < 0 && errno != ENOENT) {
    /* STAT ERROR */
    int xerrno = errno;
    pr_log_debug(DEBUG3, MOD_TRASH_VERSION ": error checking '%s': %s", dir, strerror(xerrno));
    errno = xerrno;
    return -1;
  }

  if (result == 0) {
    /* Directory already exists */
    return 1;
  }

  if (pr_fsio_mkdir(dir, mode) < 0) {
    int xerrno = errno;
    pr_log_debug(DEBUG3, MOD_TRASH_VERSION ": error creating '%s': %s", dir, strerror(xerrno));
    errno = xerrno;
    return -1;
  }

  return 0;
}

static int create_path(pool *p, const char *path) {
  char *curr_path, *tmp_path;

  tmp_path = pstrdup(p, path);
  curr_path = "/";

  while (tmp_path && *tmp_path) {
    char *curr_dir;
    int result, statresult;
    mode_t mode;
    struct stat st;

    curr_dir = strsep(&tmp_path, "/");
    curr_path = pdircat(p, curr_path, curr_dir, NULL);

    statresult = pr_fsio_stat(curr_path, &st);
    if (statresult < 0 && errno == ENOENT) {

      /* GET MODE OF CURRENT DIR */
      mode = st.st_mode & (S_ISVTX | S_IRWXU | S_IRWXG | S_IRWXO);

      result = create_dir(curr_path, mode);
      if (result < 0) {
        /* MKDIR ERROR */
        int xerrno = errno;
        errno = xerrno;
        return -1;
      }

    } else if (statresult < 0) {
      /* STAT ERROR */
      int xerrno = errno;
      pr_log_debug(DEBUG3, MOD_TRASH_VERSION ": error checking '%s': %s", curr_path, strerror(xerrno));
      errno = xerrno;
      return -1;
    }
  }

  return 0;
}

/* UTIMES GID PRIVS_ROOT HACK */
/* COPIED & MODIFIED FROM mod_facts.c LINES 610-680 */
static int utimes_gid_rootprivs(pool *p, const char *path, struct timeval *tvs) {

  /* If the utimes(2) call failed because the process UID doesn't
   * match the file UID, then check to see if the GIDs match (and that
   * the file has group write permissions).
   * This can be alleviated in two ways: a) if mod_cap is present,
   * enable the CAP_FOWNER capability for the session, or b) use root
   * privs. */

  int xerrno = errno;
  struct stat st;
  int matching_gid = FALSE;
  int res;

  pr_fs_clear_cache();
  if (pr_fsio_stat(path, &st) < 0) {
    errno = xerrno;
    return -1;
  }

  /* Be sure to check the primary and all the supplemental groups to
   * which this session belongs. */
  if (st.st_gid == session.gid) {
    matching_gid = TRUE;

  } else {
    register unsigned int i;
    gid_t *gids;

    gids = session.gids->elts;
    for (i = 0; i < session.gids->nelts; i++) {
      if (st.st_gid == gids[i]) {
        matching_gid = TRUE;
        break;
      }
    }
  }

  if (matching_gid == TRUE && (st.st_mode & S_IWGRP)) {
    int merrno = 0;

    /* Try the utimes(2) call again, this time with root privs. */
    pr_signals_block();
    PRIVS_ROOT
    res = pr_fsio_utimes(path, tvs);
    if (res < 0) {
      merrno = errno;
    }
    PRIVS_RELINQUISH
    pr_signals_unblock();

    if (res == 0)
      return 0;

    pr_log_debug(DEBUG2, MOD_TRASH_VERSION ": error modifying modify fact for '%s': %s", path, strerror(merrno));
    errno = xerrno;
    return -1;
  }

  errno = xerrno;
  return -1;
}




/* CONFIG HANDLER TrashCmdResponseDele */
MODRET set_trashcmdresponsedele(cmd_rec *cmd) {
  char *responsemsg = NULL;
  config_rec *c = NULL;

  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT|CONF_GLOBAL|CONF_DIR|CONF_ANON|CONF_VIRTUAL);

  responsemsg = cmd->arg;

  if (!strlen(responsemsg) > 0) {
    CONF_ERROR(cmd, "not set");
  }

  c = add_config_param_str(cmd->argv[0], 1, (void *) responsemsg);
  c->flags |= CF_MERGEDOWN;

  return PR_HANDLED(cmd);
}

/* CONFIG HANDLER TrashCmdResponseDeleErr */
MODRET set_trashcmdresponsedeleerr(cmd_rec *cmd) {
  char *responsemsg = NULL;
  config_rec *c = NULL;

  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT|CONF_GLOBAL|CONF_DIR|CONF_ANON|CONF_VIRTUAL);

  responsemsg = cmd->arg;

  if (!strlen(responsemsg) > 0) {
    CONF_ERROR(cmd, "not set");
  }

  c = add_config_param_str(cmd->argv[0], 1, (void *) responsemsg);
  c->flags |= CF_MERGEDOWN;

  return PR_HANDLED(cmd);
}

/* CONFIG HANDLER TrashDirectory */
MODRET set_trashdirectory(cmd_rec *cmd) {
  char *trashdirectory = NULL;
  config_rec *c = NULL;

  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT|CONF_GLOBAL|CONF_DIR|CONF_ANON|CONF_VIRTUAL);

  trashdirectory = cmd->arg;

  if (!strlen(trashdirectory) > 0) {
    CONF_ERROR(cmd, "is not set");
  }

  if (trashdirectory[0] != '/') {
    CONF_ERROR(cmd, "must start with '/'");
  }

  c = add_config_param_str(cmd->argv[0], 1, (void *) trashdirectory);
  c->flags |= CF_MERGEDOWN;

  return PR_HANDLED(cmd);
}

/* CONFIG HANDLER TrashEnable */
MODRET set_trashenable(cmd_rec *cmd) {
  int bool = -1;
  config_rec *c = NULL;

  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT|CONF_GLOBAL|CONF_DIR|CONF_ANON|CONF_VIRTUAL);

  bool = get_boolean(cmd, 1);
  if (bool == -1)
    CONF_ERROR(cmd, "requires a boolean value");

  c = add_config_param(cmd->argv[0], 1, NULL);
  c->argv[0] = palloc(c->pool, sizeof(int));
  *((int *) c->argv[0]) = bool;
  /*c = add_config_param(cmd->argv[0], 1, (void *) bool);*/
  c->flags |= CF_MERGEDOWN;

  return PR_HANDLED(cmd);
}

/* CONFIG HANDLER TrashEngine */
MODRET set_trashengine(cmd_rec *cmd) {
  int bool = -1;
  config_rec *c = NULL;

  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT|CONF_GLOBAL|CONF_VIRTUAL);

  bool = get_boolean(cmd, 1);
  if (bool == -1)
    CONF_ERROR(cmd, "requires a boolean value");

  c = add_config_param(cmd->argv[0], 1, NULL);
  c->argv[0] = palloc(c->pool, sizeof(int));
  *((int *) c->argv[0]) = bool;
  /*c = add_config_param(cmd->argv[0], 1, (void *) bool);*/
  c->flags |= CF_MERGEDOWN;

  return PR_HANDLED(cmd);
}

/* CONFIG HANDLER TrashErrorDecline */
MODRET set_trasherrordecline(cmd_rec *cmd) {
  int bool = -1;
  config_rec *c = NULL;

  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT|CONF_GLOBAL|CONF_DIR|CONF_ANON|CONF_VIRTUAL);

  bool = get_boolean(cmd, 1);
  if (bool == -1)
    CONF_ERROR(cmd, "requires a boolean value");

  c = add_config_param(cmd->argv[0], 1, NULL);
  c->argv[0] = palloc(c->pool, sizeof(int));
  *((int *) c->argv[0]) = bool;
  /*c = add_config_param(cmd->argv[0], 1, (void *) bool);*/
  c->flags |= CF_MERGEDOWN;

  return PR_HANDLED(cmd);
}

/* CONFIG HANDLER TrashPreservePaths */
MODRET set_trashpreservepaths(cmd_rec *cmd) {
  int bool = -1;
  config_rec *c = NULL;

  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT|CONF_GLOBAL|CONF_DIR|CONF_ANON|CONF_VIRTUAL);

  bool = get_boolean(cmd, 1);
  if (bool == -1)
    CONF_ERROR(cmd, "requires a boolean value");

  c = add_config_param(cmd->argv[0], 1, NULL);
  c->argv[0] = palloc(c->pool, sizeof(int));
  *((int *) c->argv[0]) = bool;
  /*c = add_config_param(cmd->argv[0], 1, (void *) bool);*/
  c->flags |= CF_MERGEDOWN;

  return PR_HANDLED(cmd);
}

/* CONFIG HANDLER TrashSetFileTime */
MODRET set_trashsetfiletime(cmd_rec *cmd) {
  char *updatefiletime = NULL;
  config_rec *c = NULL;

  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT|CONF_GLOBAL|CONF_DIR|CONF_ANON|CONF_VIRTUAL);

  updatefiletime = cmd->arg;

  if (!strlen(updatefiletime) > 0) {
    CONF_ERROR(cmd, "not set");
  }

  if (strcmp(updatefiletime, "atime") != 0 && strcmp(updatefiletime, "mtime") != 0 && strcmp(updatefiletime, "off") != 0) {
    CONF_ERROR(cmd, "not valid. Must be one of: atime, mtime or off");
  }

  c = add_config_param_str(cmd->argv[0], 1, (void *) updatefiletime);
  c->flags |= CF_MERGEDOWN;

  return PR_HANDLED(cmd);
}


/* PRECMD */
MODRET trash_precmd(cmd_rec *cmd) {
  config_rec *conf_trashenable = NULL;

  conf_trashenable = find_config(CURRENT_CONF, CONF_PARAM, "TrashEnable", FALSE);

  if (trashengine == TRUE) {
    pr_log_debug(DEBUG3, MOD_TRASH_VERSION ": TrashEngine on");

    if (conf_trashenable != NULL) {

      if (!conf_trashenable->argv[0]) {
        pr_log_debug(DEBUG3, MOD_TRASH_VERSION ": TrashEnable off");
        usetrash = FALSE;

      } else {
        pr_log_debug(DEBUG3, MOD_TRASH_VERSION ": TrashEnable on");
        usetrash = TRUE;
      }

    } else {
      pr_log_debug(DEBUG3, MOD_TRASH_VERSION ": TrashEnable not set");
      usetrash = FALSE;
    }

  } else {
    pr_log_debug(DEBUG3, MOD_TRASH_VERSION ": TrashEngine off");
    usetrash = FALSE;
  }

  return PR_DECLINED(cmd);
}




/* MAIN BIT */
MODRET trash_dele(cmd_rec *cmd) {

  char *file, *filepath, *renamedest, *renamesrc, *responsemsg, *responsemsgerr, *trashdirectory, *trashsetfiletime, *utimeerr;
  int renameresult, statresult, trasherrordecline, trashpreservepaths;
  struct stat st;
  struct timeval tvs[2];
  struct timeval timenow;
  unsigned char *authenticated;
  long long filemtime, filemtimeusec;
  config_rec *conf_trashcmdresponsedele = NULL, *conf_trashcmdresponsedeleerr = NULL, *conf_trashdirectory = NULL, *conf_trasherrordecline = NULL, *conf_trashpreservepaths = NULL, *conf_trashsetfiletime = NULL;

  /* TrashEngine or TrashEnable FALSE? */
  if (!usetrash)
    return PR_DECLINED(cmd);

  /* GET CONF TrashCmdResponseDele */
  conf_trashcmdresponsedele = find_config(CURRENT_CONF, CONF_PARAM, "TrashCmdResponseDele", FALSE);
  if (!conf_trashcmdresponsedele) {
    responsemsg = "DELE command successful";
  } else {
    responsemsg = conf_trashcmdresponsedele->argv[0];
  }

  /* GET CONF TrashCmdResponseDeleErr */
  conf_trashcmdresponsedeleerr = find_config(CURRENT_CONF, CONF_PARAM, "TrashCmdResponseDeleErr", FALSE);
  if (!conf_trashcmdresponsedeleerr) {
    responsemsgerr = "DELE command failed";
  } else {
    responsemsgerr = conf_trashcmdresponsedeleerr->argv[0];
  }

  /* GET CONF TrashErrorDecline */
  conf_trasherrordecline = find_config(CURRENT_CONF, CONF_PARAM, "TrashErrorDecline", FALSE);
  if (conf_trasherrordecline != NULL) {
    if (conf_trasherrordecline->argv[0]) {
      pr_log_debug(DEBUG3, MOD_TRASH_VERSION ": TrashErrorDecline on");
      trasherrordecline = TRUE;
    } else {
      pr_log_debug(DEBUG3, MOD_TRASH_VERSION ": TrashErrorDecline off");
      trasherrordecline = FALSE;
    }
  } else {
    /* DEFAULT FALSE */
    pr_log_debug(DEBUG3, MOD_TRASH_VERSION ": TrashErrorDecline not set, defaults to off");
    trasherrordecline = FALSE;
  }

  /* GET CONF TrashDirectory */
  conf_trashdirectory = find_config(CURRENT_CONF, CONF_PARAM, "TrashDirectory", FALSE);
  if (!conf_trashdirectory) {

    pr_log_debug(DEBUG3, MOD_TRASH_VERSION ": TrashDirectory not set");

    /* DECLINE OR ERROR */
    if (trasherrordecline == TRUE) {
      return PR_DECLINED(cmd);
    } else {
      pr_response_add_err(R_550, responsemsgerr);
      return PR_ERROR(cmd);
    }

  } else {
    trashdirectory = dir_canonical_path(cmd->tmp_pool, conf_trashdirectory->argv[0]);

    /* DIR CHECK STAT TrashDirectory */
    if (!pr_fsio_stat(trashdirectory, &st) == 0 && !S_ISDIR(st.st_mode)) {
      /* DIR STAT ERROR */
      pr_log_debug(DEBUG3, MOD_TRASH_VERSION ": TrashDirectory '%s' not valid: %s", trashdirectory, strerror(errno));

      /* DECLINE OR ERROR */
      if (trasherrordecline == TRUE) {
        return PR_DECLINED(cmd);
      } else {
        pr_response_add_err(R_550, responsemsgerr);
        return PR_ERROR(cmd);
      }
    }
  }

  /* GET CONF TrashPreservePaths */
  conf_trashpreservepaths = find_config(CURRENT_CONF, CONF_PARAM, "TrashPreservePaths", FALSE);
  if (conf_trashpreservepaths != NULL) {
    if (conf_trashpreservepaths->argv[0]) {
      pr_log_debug(DEBUG3, MOD_TRASH_VERSION ": TrashPreservePaths on");
      trashpreservepaths = TRUE;
    } else {
      pr_log_debug(DEBUG3, MOD_TRASH_VERSION ": TrashPreservePaths off");
      trashpreservepaths = FALSE;
    }
  } else {
    /* DEFAULT TRUE */
    pr_log_debug(DEBUG3, MOD_TRASH_VERSION ": TrashPreservePaths not set, defaults to on");
    trashpreservepaths = TRUE;
  }

  /* GET CONF TrashSetFileTime */
  conf_trashsetfiletime = find_config(CURRENT_CONF, CONF_PARAM, "TrashSetFileTime", FALSE);
  if (!conf_trashsetfiletime) {
    trashsetfiletime = "atime";
  } else {
    trashsetfiletime = conf_trashsetfiletime->argv[0];
  }

  /* AUTH CHECK. NOT SURE WHAT THIS IS REALLY FOR. NEEDED ON EACH COMMAND? */
  authenticated = get_param_ptr(cmd->server->conf, "authenticated", FALSE);
  if (authenticated == NULL || *authenticated == FALSE) {
    pr_response_add_err(R_530, _("Please login with USER and PASS"));
    errno = EACCES;
    return PR_ERROR(cmd);
  }

  /* GET CURRENT TIME */
  gettimeofday(&timenow, NULL);

  /* COMMAND ARG CHECK - MAY CONTAIN SPACES */
  if (cmd->argc <= 1 || strlen(cmd->arg) == 0) {
    /* ARG NOT VALID */

    pr_log_debug(DEBUG3, MOD_TRASH_VERSION ": File argument not valid '%s'", cmd->arg);
    /* DECLINE OR ERROR */
    if (trasherrordecline == TRUE) {
      return PR_DECLINED(cmd);
    } else {
      pr_response_add_err(R_501, "File argument not valid '%s'", cmd->arg);
      return PR_ERROR(cmd);
    }

  } else {
    /* ARG PRESENT */

    file = cmd->arg;
    filepath = dir_canonical_path(cmd->tmp_pool, cmd->arg);

    /* FILE CHECK STAT */
    if (pr_fsio_stat(filepath, &st) == 0 && S_ISREG(st.st_mode)) {
      /* FILE OK */

      /* GET SOURCE PATH WITHOUT FILENAME */
      char *ptr = strrchr(filepath, '/');
      renamesrc = pstrndup(cmd->tmp_pool, filepath, ptr-filepath);
      /*pr_log_debug(DEBUG3, MOD_TRASH_VERSION ": file OK '%s', path '%s'", filepath, renamesrc);*/

      /* GET FILE mtime FOR TrashSetFileTime */
      filemtime = st.st_mtime;
      /*filemtimeusec = st.st_mtim.tv_nsec / 1000;*/

      /* TrashPreservePaths ON */
      if (trashpreservepaths == TRUE) {

        /* APPEND TrashDirectory TO PATH AS DESTINATION */
        renamedest = pstrcat(cmd->tmp_pool, trashdirectory, renamesrc, NULL);

        /* ADD TRAILING / TO renamedest IF NOT PRESENT */
        if (renamedest[(strlen(renamedest) - 1)] != '/' ) {
          renamedest = pstrcat(cmd->tmp_pool, renamedest, "/", NULL);
        }

        /* DEST PATH EXIST UNDER TRASH? */
        pr_fs_clear_cache();
        statresult = pr_fsio_stat(renamedest, &st);
        if (statresult < 0 && errno == ENOENT) {
          /* DIR STAT ERROR, PATH NOT EXIST */
          pr_log_debug(DEBUG3, MOD_TRASH_VERSION ": path not exist '%s'", renamedest);

          /* CREATE PATH */
          if (create_path(cmd->tmp_pool, renamedest) < 0) {
            /* CREATE PATH ERROR */
            pr_log_debug(DEBUG3, MOD_TRASH_VERSION ": error creating path '%s': %s", renamedest, strerror(errno));
            /* DECLINE OR ERROR */
            if (trasherrordecline == TRUE) {
              return PR_DECLINED(cmd);
            } else {
              pr_response_add_err(R_550, responsemsgerr);
              return PR_ERROR(cmd);
            }
          }

        } else if (statresult < 0) {
          /* DIR STAT ERROR */
          pr_log_debug(DEBUG3, MOD_TRASH_VERSION ": error checking '%s': %s", renamedest, strerror(errno));
          /* DECLINE OR ERROR */
          if (trasherrordecline == TRUE) {
            return PR_DECLINED(cmd);
          } else {
            pr_response_add_err(R_550, responsemsgerr);
            return PR_ERROR(cmd);
          }
        }

      } else {
        /* TrashPreservePaths OFF */
        renamedest = trashdirectory;
      }

      /* APPEND file TO renamedest AND renamesrc */
      renamedest = pstrcat(cmd->tmp_pool, renamedest, file, NULL);
      renamesrc = pstrcat(cmd->tmp_pool, renamesrc, file, NULL);

      /* TrashSetFileTime */
      if (strlen(trashsetfiletime) > 0 && strcmp(trashsetfiletime, "off") != 0) {

        if (strcmp(trashsetfiletime, "mtime") == 0) {
          /* NEW atime+mtime */
          tvs[0].tv_sec = timenow.tv_sec;
          tvs[0].tv_usec = timenow.tv_usec;
          tvs[1].tv_sec = timenow.tv_sec;
          tvs[1].tv_usec = timenow.tv_usec;
        } else {
          /* NEW atime, USE PRESERVED mtime */
          tvs[0].tv_sec = timenow.tv_sec;
          tvs[0].tv_usec = timenow.tv_usec;
          tvs[1].tv_sec = filemtime;
          tvs[1].tv_usec = 0;
          /*tvs[1].tv_usec = filemtimeusec;*/
        }

        /* SET FILE TIMES */
        pr_fs_clear_cache();
        if (pr_fsio_utimes(file, tvs) < 0) {
          /* UTIMES ERROR */
          /* GET errno TO STRING FOR DEBUG */

          switch (errno) {
            case EACCES: utimeerr = "EACCES";
              break;
            case ENOENT: utimeerr = "ENOENT";
              break;
            case EPERM: utimeerr = "EPERM";
              break;
            case EROFS: utimeerr = "EROFS";
              break;
          }

          pr_log_debug(DEBUG3, MOD_TRASH_VERSION ": error setting %s for file '%s': %s %s", trashsetfiletime, file, utimeerr, strerror(errno));

          /* UTIMES EPERM ERROR? ATTEMPT GID/PRIVS_ROOT WORKAROUND */
          if (errno == EPERM) {

            if (utimes_gid_root(cmd->tmp_pool, file, tvs) > 0) {
              /* UTIMES OK */
              pr_log_debug(DEBUG3, MOD_TRASH_VERSION ": %s set for file '%s' using PRIVS_ROOT", trashsetfiletime, file);
            }
          }

          /* DECLINE? */
          if (trasherrordecline == TRUE)
            return PR_DECLINED(cmd);

          pr_response_add_err(R_550, responsemsgerr);
          return PR_ERROR(cmd);

        } else {
          /* UTIMES OK */
          pr_log_debug(DEBUG3, MOD_TRASH_VERSION ": %s set for file '%s'", trashsetfiletime, file);
        }
      }

      /* DO RENAME / TRASH */
      renameresult = pr_fsio_rename(filepath, renamedest);
      if (renameresult < 0) {
        /* RENAME ERROR */

        if (errno == EXDEV) {
          /* EXTERNAL DEVICE, ATTEMPT COPY-UNLINK */

          pr_log_debug(DEBUG3, MOD_TRASH_VERSION ": error renaming, attempt copy-unlink");

          if (pr_fs_copy_file(filepath, renamedest) < 0) {
            /* COPY ERROR */
            pr_log_debug(DEBUG3, MOD_TRASH_VERSION ": error copying file '%s' to trash '%s': %s", filepath, renamedest, strerror(errno));

            /* DECLINE? */
            if (trasherrordecline == TRUE)
              return PR_DECLINED(cmd);

            pr_response_add_err(R_550, responsemsgerr);
            return PR_ERROR(cmd);
          }

          if (pr_fsio_unlink(filepath) < 0) {
            /* UNLINK ERROR */
            pr_log_debug(DEBUG3, MOD_TRASH_VERSION ": error unlinking file '%s': %s", filepath, strerror(errno));

            /* DECLINE? */
            if (trasherrordecline == TRUE)
              return PR_DECLINED(cmd);

            pr_response_add_err(R_550, responsemsgerr);
            return PR_ERROR(cmd);
          }

        } else {
          /* RENAME OTHER ERROR */
          pr_log_debug(DEBUG3, MOD_TRASH_VERSION ": error renaming file '%s' to trash directory '%s': %s", filepath, renamedest, strerror(errno));

          /* DECLINE? */
          if (trasherrordecline == TRUE)
            return PR_DECLINED(cmd);

          pr_response_add_err(R_550, responsemsgerr);
          return PR_ERROR(cmd);
        }
      }

    } else {
      /* FILE STAT ERROR */
      pr_log_debug(DEBUG3, MOD_TRASH_VERSION ": File '%s' not valid: %s", file, strerror(errno));

      /* DECLINE? */
      if (trasherrordecline == TRUE)
        return PR_DECLINED(cmd);

      pr_response_add_err(R_550, "File '%s' not valid", file);
      return PR_ERROR(cmd);
    }
  }

  /* HANDLED */
  pr_response_add(R_250, responsemsg);
  return PR_HANDLED(cmd);
}



/* SESSION INIT */
static int trash_sess_init(void) {
  unsigned char *conf_trashengine = NULL;

  conf_trashengine = get_param_ptr(main_server->conf, "TrashEngine", FALSE);
  if (conf_trashengine != NULL && *conf_trashengine == TRUE) {
    trashengine = TRUE;
  } else {
    trashengine = FALSE;
  }

  /*config_rec *conf_trashengine = NULL;*/

  /*conf_trashengine = find_config(CURRENT_CONF, CONF_PARAM, "TrashEngine", FALSE);*/
  /*conf_trashengine = find_config(main_server->conf, CONF_PARAM, "TrashEngine", FALSE);*/

/*  while (conf_trashengine) {*/
/*
  if (conf_trashengine != NULL) {
    if (conf_trashengine->argv[0]) {
      trashengine = TRUE;
    } else {
      trashengine = FALSE;
    }
  } else {
    trashengine = FALSE;
  }*/

/*    conf_trashengine = find_config_next(conf_trashengine, conf_trashengine->next, CONF_PARAM, "TrashEngine", FALSE);
  }*/

  return 0;
}



/* CONFIG HANDLER TABLE */
static conftable trash_conftab[] = {
  { "TrashCmdResponseDele",	set_trashcmdresponsedele,	NULL },
  { "TrashCmdResponseDeleErr",	set_trashcmdresponsedeleerr,	NULL },
  { "TrashDirectory",		set_trashdirectory,		NULL },
  { "TrashErrorDecline",	set_trasherrordecline,		NULL },
  { "TrashEnable",		set_trashenable,		NULL },
  { "TrashEngine",		set_trashengine,		NULL },
  { "TrashPreservePaths",	set_trashpreservepaths,		NULL },
  { "TrashSetFileTime",		set_trashsetfiletime,		NULL },
  { NULL }
};

/* COMMAND HANDLER TABLE */
static cmdtable trash_cmdtab[] = {
  { PRE_CMD,		C_DELE,	G_NONE,	trash_precmd,	 FALSE,	FALSE },
/*  { PRE_CMD,		C_RMD,	G_NONE,	trash_precmd,	 FALSE,	FALSE },*/
  { CMD,		C_DELE,	G_NONE,	trash_dele,	 FALSE,	FALSE },
/*  { CMD,		C_RMD,	G_NONE,	trash_mv_dir,	 FALSE,	FALSE },*/
/*  { LOG_CMD,		C_DELE,	G_NONE,	readme_post_cmd, FALSE,	FALSE },*/
/*  { LOG_CMD_ERR,	C_DELE,	G_NONE,	readme_post_cmd, FALSE,	FALSE },*/
  { 0, NULL }
};

module trash_module = {
  NULL, NULL,/* Always NULL */
  0x20,/* Module API version */
  "trash",/* Module name */
  trash_conftab,/* Module configuration directive table */
  trash_cmdtab,/* Module command handler table */
  NULL,/* Module auth handler table */
  NULL,/* Module initialization */
  trash_sess_init,/* Session initialization */
  MOD_TRASH_VERSION/* Module version */
};
