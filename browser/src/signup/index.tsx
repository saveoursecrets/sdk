import React, { useState } from "react";

import { WorkerProps } from "../props";

import SignupCleanup from "./cleanup";
import Accept from "./accept";
import PrivateKey from "./private-key";
import VerifyKey from "./verify-key";
import EncryptionPassphrase from "./encryption-passphrase";
import VerifyEncryption from "./verify-encryption";

enum SignupStep {
  ACCEPT = 1,
  PRIVATE_KEY = 2,
  VERIFY_KEY = 3,
  PASSPHRASE = 4,
  VERIFY_ENCRYPTION = 5,
  COMPLETE = 6,
}

const signupSteps = [
  SignupStep.ACCEPT,
  SignupStep.PRIVATE_KEY,
  SignupStep.VERIFY_KEY,
  SignupStep.PASSPHRASE,
  SignupStep.VERIFY_ENCRYPTION,
  SignupStep.COMPLETE,
];

export type StepProps = {
  nextStep: () => void;
} & WorkerProps;

function SignupStepView(props: WorkerProps) {
  const { worker } = props;
  const [stepIndex, setStepIndex] = useState(0);
  const nextStep = () => {
    if (stepIndex < signupSteps.length - 1) {
      setStepIndex(stepIndex + 1);
    }
  };
  const step = signupSteps[stepIndex];

  switch (step) {
    case SignupStep.ACCEPT:
      return <Accept worker={worker} nextStep={nextStep} />;
    case SignupStep.PRIVATE_KEY:
      return <PrivateKey worker={worker} nextStep={nextStep} />;
    case SignupStep.VERIFY_KEY:
      return <VerifyKey worker={worker} nextStep={nextStep} />;
    case SignupStep.PASSPHRASE:
      return <EncryptionPassphrase worker={worker} nextStep={nextStep} />;
    case SignupStep.VERIFY_ENCRYPTION:
      return <VerifyEncryption worker={worker} nextStep={nextStep} />;
    case SignupStep.COMPLETE:
      return (
        <p>
          Congratulations, signup is completed! TODO: send vault to create new
          account on remote server
        </p>
      );
  }
}

export default function SignupView(props: WorkerProps) {
  const { worker } = props;
  return (
    <>
      <SignupStepView worker={worker} />
      <SignupCleanup />
    </>
  );
}
