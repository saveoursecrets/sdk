import React from "react";
import ReactDOM from "react-dom";
import { HashRouter, Routes, Route } from "react-router-dom";
import { Provider } from "react-redux";

import store from "./store";

import WorkerProvider from "./worker-provider";

const NotFound = () => <h3>Page not found</h3>;

const App = () => {
  if (window.Worker) {

            //<Route path="/" element={<Home />} />
            //<Route path="/keygen/:uuid" element={<Keygen />} />
            //<Route path="/sign/:address" element={<Sign />} />

    return (
      <div>
        <h1>
          <a href="/">SOS3 Sandbox</a>
        </h1>
        <hr />
        <WorkerProvider>
          <Routes>
            <Route path="*" element={<NotFound />} />
          </Routes>
        </WorkerProvider>
      </div>
    );
  } else {
    return <p>Your browser does not support web workers.</p>;
  }
};

ReactDOM.render(
  <React.StrictMode>
    <Provider store={store}>
      <HashRouter>
        <App />
      </HashRouter>
    </Provider>
  </React.StrictMode>,
  document.querySelector("main")
);
