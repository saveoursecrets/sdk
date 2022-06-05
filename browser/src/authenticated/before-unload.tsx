import React, { useEffect } from "react";
import { useSelector } from "react-redux";
import { batchSelector } from "../store/batch";

function onBeforeUnload(e: Event) {
  e.preventDefault();
  return event.returnValue = true;
}

export default function BeforeUnload(): null {
  const { totalChanges } = useSelector(batchSelector);
  useEffect(() => {
    window.removeEventListener("beforeunload", onBeforeUnload);
    if (totalChanges > 0) {
      window.addEventListener("beforeunload", onBeforeUnload);
    }
  }, [totalChanges]);
  return null;
}
