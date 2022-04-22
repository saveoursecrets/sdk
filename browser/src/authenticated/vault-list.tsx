import React from "react";
import { useSelector, useDispatch } from "react-redux";
import { useNavigate } from "react-router-dom";

import {
  List,
  ListItem,
  ListItemButton,
  ListItemIcon,
  ListItemText,
  ListSubheader,
  Divider,
  Stack,
  IconButton,
} from "@mui/material";

import AddIcon from "@mui/icons-material/Add";
import LockIcon from "@mui/icons-material/Lock";
import LockOpenIcon from "@mui/icons-material/LockOpen";

import { VaultStorage, vaultsSelector, setCurrent } from "../store/vaults";
import { accountSelector, setSelectedIndex } from "../store/account";
import { setDialogVisible, NEW_VAULT } from "../store/dialogs";

export default function VaultList() {
  const { account, selectedIndex } = useSelector(accountSelector);
  const navigate = useNavigate();
  const dispatch = useDispatch();

  const { summaries } = account;

  const showNewVault = () => {
    dispatch(setDialogVisible([NEW_VAULT, true, null]));
  };

  const openVault = (vault: Summary, index: number) => {
    dispatch(setSelectedIndex(index));
    navigate(`/vault/${vault.id}`);
  };

  const SubHeader = () => {
    return (
      <>
        <ListSubheader sx={{ paddingRight: 1 }}>
          <Stack
            direction="row"
            justifyContent="space-between"
            alignItems="center"
          >
            Vaults
            <IconButton sx={{ width: 40, height: 40 }} onClick={showNewVault}>
              <AddIcon />
            </IconButton>
          </Stack>
        </ListSubheader>
        <Divider />
      </>
    );
  };

  return (
    <List component="nav" subheader={<SubHeader />}>
      {summaries.map((vault: Summary, index: number) => {
        return (
          <div key={vault.id}>
            <ListItem
              selected={selectedIndex === index}
              component="div"
              disablePadding
            >
              <ListItemButton onClick={() => openVault(vault, index)}>
                <ListItemIcon>
                  {vault.locked ? <LockIcon /> : <LockOpenIcon />}
                </ListItemIcon>
                <ListItemText primary={vault.name} />
              </ListItemButton>
            </ListItem>
            <Divider light />
          </div>
        );
      })}
    </List>
  );
}
