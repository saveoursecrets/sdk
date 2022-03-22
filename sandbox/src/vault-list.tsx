import React from "react";
import { useSelector, useDispatch } from "react-redux";
import { WebVault } from 'sos-wasm';

import { VaultWorker } from './worker';
import { VaultStorage, vaultsSelector, addVault } from './store/vaults';

import List from '@mui/material/List';
import ListItem from '@mui/material/ListItem';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';

interface VaultListProps {}

export default function VaultList(props: VaultListProps) {
  const { vaults } = useSelector(vaultsSelector);

  return <List>
    {
      vaults.map((vault: VaultStorage) => {
        return <ListItem key={vault.uuid}>{vault.uuid}</ListItem>;
      })
    }

        </List>;

          //{['Inbox', 'Starred', 'Send email', 'Drafts'].map((text, index) => (
            //<ListItem button key={text}>
              //<ListItemIcon>
                //{index % 2 === 0 ? <InboxIcon /> : <MailIcon />}
              //</ListItemIcon>
              //<ListItemText primary={text} />
            //</ListItem>
          //))}
  /*
  return <ul>
  </ul>;
  */
}
