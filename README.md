# ProFTPD mod_trash module
Implements a crude "trash can" by intercepting FTP `DELE` commands
and moves files to a specified directory instead of deleting.
File move (rename) to be faster at FS-level than a copy/delete.

This was active code running on a multi-user ProFTPD instance for
several years from around 2010 or so, and I remember it saving us
from a couple of large accidental deletions via FileZilla.
I cannot guarantee the completeness or stability of this code though.
I got it to the point of "works well enough for us" but I remember
not being completely happy with the config naming and consistency
of logging output.
I always intended to revisit this and submit to `proftpd/contrib/`.
I will do so at some point when I get motivation to learn C again
for the 20th time.

## Configuration
```
TrashEngine                on|off
TrashEnable                on|off
TrashDirectory             path
TrashCmdResponseDele       "File deleted to trash"
TrashCmdResponseDeleErr    "File delete failed"
TrashErrorDecline          on|off <default: off>
TrashPreservePaths         on|off <default: on>
TrashSetFileTime           atime|mtime|off <default: atime>

# Not implemented:
TrashKeepMultiples        on|off <default: off>
TrashInterceptOverwrites  on|off <default: off>
```
