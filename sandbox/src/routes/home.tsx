import React from "react";
import { VaultWorker } from '../worker';
import { WorkerContext } from "../worker-provider";

interface CreateVaultProps {
  worker: VaultWorker;
}

function CreateVault(props: CreateVaultProps) {
  const {worker} = props;

  const createVault = async () => {
    const label = "My Vault";
    const passphrase = "12345678901234567890123456789012"
    const encoder = new TextEncoder();
    const password = encoder.encode(passphrase);
    const vault = await worker.newVault(label, Array.from(password));
    console.log("create a new vault", vault);
  }

  return <button onClick={createVault}>Create vault</button>;
}

export default function Home() {
  //const navigate = useNavigate();
  //const { group } = useSelector(groupSelector);
  //const dispatch = useDispatch();
  //const websocket = useContext(WebSocketContext);

  return <>
    <h2>Vaults</h2>
    <WorkerContext.Consumer>
      {(worker) => {
        return (
          <CreateVault
            worker={worker}
          />
        );
      }}
    </WorkerContext.Consumer>
  </>;
}
