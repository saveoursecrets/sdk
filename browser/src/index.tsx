import React, { useState } from "react";
import ReactDOM from "react-dom";
import { HashRouter, Routes, Route, useNavigate } from "react-router-dom";
import { Provider, useDispatch } from "react-redux";

import { styled, useTheme, ThemeProvider } from "@mui/material/styles";
import Box from "@mui/material/Box";
import Drawer from "@mui/material/Drawer";
import CssBaseline from "@mui/material/CssBaseline";
import MuiAppBar, { AppBarProps as MuiAppBarProps } from "@mui/material/AppBar";
import Toolbar from "@mui/material/Toolbar";

import Typography from "@mui/material/Typography";
import Divider from "@mui/material/Divider";
import IconButton from "@mui/material/IconButton";
import Link from "@mui/material/Link";
import Button from "@mui/material/Button";
import { createTheme } from "@mui/material/styles";

import MenuIcon from "@mui/icons-material/Menu";
import ChevronLeftIcon from "@mui/icons-material/ChevronLeft";
import ChevronRightIcon from "@mui/icons-material/ChevronRight";
import AddIcon from "@mui/icons-material/Add";

import { WebVault } from "sos-wasm";
import store from "./store";
import Home from "./home";
import Vault from "./vault";
import NewVaultDialog from "./new-vault-dialog";
import WorkerProvider, { WorkerContext } from "./worker-provider";
import VaultList from "./vault-list";
import { VaultWorker } from "./worker";
import { addVault } from "./store/vaults";
import { NewVaultResult } from "./types";

const NotFound = () => <h3>Page not found</h3>;

declare module "@mui/material/styles" {
  interface Theme {
    status: {
      //danger: string;
    };
  }
  interface ThemeOptions {
    status?: {
      //danger?: string;
    };
  }
}

const theme = createTheme({
  palette: {
    mode: "dark",
  },
  status: {
    //danger: orange[500],
  },
});

const drawerWidth = 240;

const Main = styled("main", { shouldForwardProp: (prop) => prop !== "open" })<{
  open?: boolean;
}>(({ theme, open }) => ({
  flexGrow: 1,
  padding: theme.spacing(3),
  transition: theme.transitions.create("margin", {
    easing: theme.transitions.easing.sharp,
    duration: theme.transitions.duration.leavingScreen,
  }),
  marginLeft: `-${drawerWidth}px`,
  ...(open && {
    transition: theme.transitions.create("margin", {
      easing: theme.transitions.easing.easeOut,
      duration: theme.transitions.duration.enteringScreen,
    }),
    marginLeft: 0,
  }),
}));

interface AppBarProps extends MuiAppBarProps {
  open?: boolean;
}

const AppBar = styled(MuiAppBar, {
  shouldForwardProp: (prop) => prop !== "open",
})<AppBarProps>(({ theme, open }) => ({
  transition: theme.transitions.create(["margin", "width"], {
    easing: theme.transitions.easing.sharp,
    duration: theme.transitions.duration.leavingScreen,
  }),
  ...(open && {
    width: `calc(100% - ${drawerWidth}px)`,
    marginLeft: `${drawerWidth}px`,
    transition: theme.transitions.create(["margin", "width"], {
      easing: theme.transitions.easing.easeOut,
      duration: theme.transitions.duration.enteringScreen,
    }),
  }),
}));

const DrawerHeader = styled("div")(({ theme }) => ({
  display: "flex",
  alignItems: "center",
  padding: theme.spacing(0, 1),
  // necessary for content to be below app bar
  ...theme.mixins.toolbar,
  justifyContent: "flex-end",
}));

interface AppProps {
  worker: VaultWorker;
}

function App(props: AppProps) {
  const { worker } = props;
  const theme = useTheme();
  const dispatch = useDispatch();
  const navigate = useNavigate();

  const [drawerOpen, setDrawerOpen] = useState(false);
  const [newVaultDialogOpen, setNewVaultDialogOpen] = useState(false);

  const handleDrawerOpen = () => setDrawerOpen(true);
  const handleDrawerClose = () => setDrawerOpen(false);
  const openNewVaultDialog = () => setNewVaultDialogOpen(true);

  const createNewVault = async (result: NewVaultResult) => {
    setNewVaultDialogOpen(false);

    const { label, password } = result;
    const vault: WebVault = await new (worker.WebVault as any)();
    await vault.initialize(label, password);
    const uuid = await vault.id();
    const storage = { uuid, vault, label, locked: false };
    dispatch(addVault(storage));
    navigate(`/vault/${uuid}`);
  };

  return (
    <Box sx={{ display: "flex" }}>
      <CssBaseline />
      <AppBar position="fixed" open={drawerOpen}>
        <Toolbar>
          <IconButton
            color="inherit"
            aria-label="open drawer"
            onClick={handleDrawerOpen}
            edge="start"
            sx={{ mr: 2, ...(drawerOpen && { display: "none" }) }}
          >
            <MenuIcon />
          </IconButton>
          <Typography variant="h6" noWrap component="div">
            <Link href="/" color="inherit">
              SOS3
            </Link>
          </Typography>

          <Typography
            variant="h6"
            component="div"
            sx={{ flexGrow: 1 }}
          ></Typography>

          <Button onClick={openNewVaultDialog} startIcon={<AddIcon />}>
            New Vault
          </Button>
        </Toolbar>
      </AppBar>
      <Drawer
        sx={{
          width: drawerWidth,
          flexShrink: 0,
          "& .MuiDrawer-paper": {
            width: drawerWidth,
            boxSizing: "border-box",
          },
        }}
        variant="persistent"
        anchor="left"
        open={drawerOpen}
      >
        <DrawerHeader>
          <IconButton onClick={handleDrawerClose}>
            {theme.direction === "ltr" ? (
              <ChevronLeftIcon />
            ) : (
              <ChevronRightIcon />
            )}
          </IconButton>
        </DrawerHeader>
        <Divider />
        <VaultList />
      </Drawer>
      <Main open={drawerOpen}>
        <DrawerHeader />

        <Routes>
          <Route path="/" element={<Home />} />
          <Route path="/vault/:id" element={<Vault />} />
          <Route path="*" element={<NotFound />} />
        </Routes>
      </Main>

      <NewVaultDialog
        open={newVaultDialogOpen}
        handleCancel={() => setNewVaultDialogOpen(false)}
        handleOk={createNewVault}
      />
    </Box>
  );
}

ReactDOM.render(
  <React.StrictMode>
    <Provider store={store}>
      <HashRouter>
        <ThemeProvider theme={theme}>
          <WorkerProvider>
            <WorkerContext.Consumer>
              {(worker) => {
                return <App worker={worker} />;
              }}
            </WorkerContext.Consumer>
          </WorkerProvider>
        </ThemeProvider>
      </HashRouter>
    </Provider>
  </React.StrictMode>,
  document.querySelector("main")
);
