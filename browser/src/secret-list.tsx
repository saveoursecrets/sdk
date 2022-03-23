import React from "react";
import { useSelector, useDispatch } from "react-redux";
//import { useNavigate } from 'react-router-dom';

import List from "@mui/material/List";
import ListItem from "@mui/material/ListItem";
import ListItemButton from "@mui/material/ListItemButton";
import ListItemIcon from "@mui/material/ListItemIcon";
import ListItemText from "@mui/material/ListItemText";
import ListSubheader from "@mui/material/ListSubheader";
import Divider from "@mui/material/Divider";
import Stack from "@mui/material/Stack";
import Typography from "@mui/material/Typography";
import Button from "@mui/material/Button";

import AddIcon from "@mui/icons-material/Add";

import { WebVault } from "sos-wasm";
import { VaultWorker } from "./worker";
import { VaultStorage, vaultsSelector, addVault } from "./store/vaults";

export interface SecretMeta {}

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
          <Button variant="contained" component="span" startIcon={<AddIcon />}>
            New Secret
          </Button>
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
