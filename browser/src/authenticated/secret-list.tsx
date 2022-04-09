import React from "react";
import { useNavigate } from "react-router-dom";

import List from "@mui/material/List";
import ListItem from "@mui/material/ListItem";
import ListItemButton from "@mui/material/ListItemButton";
import ListItemIcon from "@mui/material/ListItemIcon";
import ListItemText from "@mui/material/ListItemText";
import Divider from "@mui/material/Divider";
import Stack from "@mui/material/Stack";
import Typography from "@mui/material/Typography";

import { SecretMeta, VaultWorker } from "../types";
import { VaultStorage } from "../store/vaults";

import SecretIcon from "./secret-icon";

interface SecretListProps {
  worker: VaultWorker;
  storage: VaultStorage;
  uuid?: string;
  maxWidth?: string | number;
}

export default function SecretList(props: SecretListProps) {
  const navigate = useNavigate();
  const { storage, maxWidth } = props;

  if (!storage) {
    return null;
  }

  const { meta } = storage;
  const secrets = new Map(Object.entries(meta));

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

  const showSecret = (uuid: string) => {
    const path = `/vault/${storage.uuid}/${uuid}`;
    navigate(path);
  };

  //<ListItemText primary={label} secondary={uuid} />

  return (
    <List component="nav" sx={{ padding: 0, maxWidth: maxWidth }}>
      {[...secrets.entries()].map((value: [string, [string, SecretMeta]]) => {
        const [, [uuid, meta]] = value;
        return (
          <div key={uuid}>
            <ListItem
              component="div"
              selected={props.uuid === uuid}
              disablePadding
              onClick={() => showSecret(uuid)}
              sx={{ overflow: "hidden" }}
            >
              <ListItemButton>
                <ListItemIcon>
                  <SecretIcon kind={meta.kind} />
                </ListItemIcon>
                <ListItemText
                  primary={meta.label}
                  primaryTypographyProps={{ noWrap: true }}
                />
              </ListItemButton>
            </ListItem>
            <Divider light />
          </div>
        );
      })}
    </List>
  );
}
