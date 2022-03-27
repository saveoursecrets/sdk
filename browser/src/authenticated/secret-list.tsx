import React from "react";

import List from "@mui/material/List";
import ListItem from "@mui/material/ListItem";
import ListItemButton from "@mui/material/ListItemButton";
import ListItemIcon from "@mui/material/ListItemIcon";
import ListItemText from "@mui/material/ListItemText";
import Divider from "@mui/material/Divider";
import Stack from "@mui/material/Stack";
import Typography from "@mui/material/Typography";

import { SearchMeta, VaultWorker } from "../types";
import { VaultStorage } from "../store/vaults";

import SecretIcon from "./secret-icon";

interface SecretListProps {
  worker: VaultWorker;
  storage: VaultStorage;
}

export default function SecretList(props: SecretListProps) {
  const { storage } = props;

  if (!storage) {
    return null;
  }

  const { index } = storage;
  const secrets = new Map(Object.entries(index));

  if (secrets.size === 0) {
    return (
      <Stack
        marginTop={4}
        alignItems="center"
        direction="column"
        justifyContent="center"
      >
        <Typography paragraph>No secrets yet</Typography>
      </Stack>
    );
  }

  return (
    <List component="nav">
      {[...secrets.entries()].map((value: [string, SearchMeta]) => {
        const [uuid, index] = value;
        return (
          <div key={uuid}>
            <ListItem component="div" disablePadding>
              <ListItemButton>
                <ListItemIcon>
                  <SecretIcon kind={index.kind} />
                </ListItemIcon>
                <ListItemText primary={index.meta.label} secondary={uuid} />
              </ListItemButton>
            </ListItem>
            <Divider light />
          </div>
        );
      })}
    </List>
  );
}
