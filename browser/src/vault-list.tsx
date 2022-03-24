import React from "react";
import { useSelector } from "react-redux";
import { useNavigate } from "react-router-dom";

import List from "@mui/material/List";
import ListItem from "@mui/material/ListItem";
import ListItemButton from "@mui/material/ListItemButton";
import ListItemIcon from "@mui/material/ListItemIcon";
import ListItemText from "@mui/material/ListItemText";
import ListSubheader from "@mui/material/ListSubheader";
import Divider from "@mui/material/Divider";

import LockIcon from "@mui/icons-material/Lock";
import LockOpenIcon from "@mui/icons-material/LockOpen";

import { VaultStorage, vaultsSelector } from "./store/vaults";

export default function VaultList() {
  const { vaults } = useSelector(vaultsSelector);
  const navigate = useNavigate();
  const openVault = (uuid: string) => {
    navigate(`/vault/${uuid}`);
  };

  return (
    <List component="nav" subheader={<ListSubheader>Vaults</ListSubheader>}>
      {vaults.map((vault: VaultStorage) => {
        return (
          <div key={vault.uuid}>
            <ListItem component="div" disablePadding>
              <ListItemButton onClick={() => openVault(vault.uuid)}>
                <ListItemIcon>
                  {vault.locked ? <LockIcon /> : <LockOpenIcon />}
                </ListItemIcon>
                <ListItemText primary={vault.label} />
              </ListItemButton>
            </ListItem>
            <Divider light />
          </div>
        );
      })}
    </List>
  );
}
