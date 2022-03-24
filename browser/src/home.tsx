import React, { useState } from "react";
import { useSelector, useDispatch } from "react-redux";
import { WebVault } from "sos-wasm";
import { useNavigate } from "react-router-dom";

import { VaultWorker } from "./worker";
import { WorkerContext } from "./worker-provider";
import { vaultsSelector, addVault } from "./store/vaults";

import Stack from "@mui/material/Stack";
import Button from "@mui/material/Button";
import TextField from "@mui/material/TextField";
import FormHelperText from "@mui/material/FormHelperText";

import Diceware from "./diceware";

export default function Home() {
  return (
    <>
      <WorkerContext.Consumer>
        {(worker) => {
          return <Diceware worker={worker} />;
        }}
      </WorkerContext.Consumer>
    </>
  );
}
