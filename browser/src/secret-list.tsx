import React from "react";

import List from "@mui/material/List";
import ListItem from "@mui/material/ListItem";
import ListSubheader from "@mui/material/ListSubheader";
import Divider from "@mui/material/Divider";
import Stack from "@mui/material/Stack";
import Typography from "@mui/material/Typography";

import AddIcon from "@mui/icons-material/Add";

import { VaultWorker } from "./worker";

export interface SecretMeta {
  label: string;
}

interface SecretListProps {
  worker: VaultWorker;
  secrets?: Map<string, SecretMeta>;
}

export default function SecretList(props: SecretListProps) {
  const { secrets } = props;

  //const navigate = useNavigate();

  /*
            <ListItemButton onClick={() => openVault(vault.uuid)}>
              <ListItemIcon>
                { vault.locked ? <LockIcon /> : <LockOpenIcon /> }
              </ListItemIcon>
              <ListItemText primary={vault.label} />
            </ListItemButton>
  */

  if (!secrets) {
    return null;
  }

  console.log("secrets", secrets);

  if (secrets.size === 0) {
    return (
      <div>
        <Stack
          spacing={2}
          marginTop={4}
          alignItems="center"
          direction="column"
          justifyContent="center"
        >
          <Typography paragraph>No secrets yet</Typography>
        </Stack>
      </div>
    );
  }

  return (
    <List component="nav" subheader={<ListSubheader>Secrets</ListSubheader>}>
      {[...secrets.entries()].map((value: [string, SecretMeta]) => {
        const [uuid, meta] = value;
        return (
          <div key={uuid}>
            <ListItem component="div" disablePadding></ListItem>
            <Divider light />
          </div>
        );
      })}
    </List>
  );
}
