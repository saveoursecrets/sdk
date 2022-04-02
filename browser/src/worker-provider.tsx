import React, { createContext, PropsWithChildren } from "react";
import * as Comlink from "comlink";

const WorkerContext = createContext(null);

type WorkerProviderProps = PropsWithChildren<Record<string, unknown>>;

console.log("Creating new worker....");
const webWorker = new Worker(new URL("./worker.ts", import.meta.url), {
  type: "module",
});
const worker = Comlink.wrap(webWorker);

const WorkerProvider = (props: WorkerProviderProps) => {
  return (
    <WorkerContext.Provider value={worker}>
      {props.children}
    </WorkerContext.Provider>
  );
};

export { WorkerContext, webWorker };

export default WorkerProvider;
