import React, { useState, useEffect } from "react";

import Box from "@mui/material/Box";
import Card from "@mui/material/Card";
import CardContent from "@mui/material/CardContent";
import Divider from "@mui/material/Divider";
import IconButton from "@mui/material/IconButton";
import Slider from "@mui/material/Slider";
import Stack from "@mui/material/Stack";
import ToggleButton from "@mui/material/ToggleButton";
import Tooltip from "@mui/material/Tooltip";
import Typography from "@mui/material/Typography";

import RefreshIcon from "@mui/icons-material/Refresh";
import NumbersIcon from "@mui/icons-material/Numbers";

import { generatePassphrase } from "./worker";

interface WordCountProps {
  words: number;
  onChange: (words: number) => void;
  onChangeCommitted: () => void;
}

function WordCount(props: WordCountProps) {
  const { words, onChange, onChangeCommitted } = props;

  function valueText(value: number) {
    return `${value} words`;
  }

  return (
    <>
      <Box sx={{ m: 2 }}>
        <Stack spacing={1} sx={{ width: "100%" }} alignItems="center">
          <Typography
            sx={{ fontSize: 14, maxWidth: 360, textAlign: "center" }}
            color="text.secondary"
            gutterBottom
          >
            Adjust the slider to use more words for your passphrase
          </Typography>

          <Box sx={{ width: 240 }}>
            <Slider
              aria-label="Words"
              defaultValue={6}
              getAriaValueText={valueText}
              valueLabelDisplay="auto"
              onChange={(e, value) => onChange(value as number)}
              onChangeCommitted={() => onChangeCommitted()}
              step={1}
              value={words}
              marks
              min={6}
              max={16}
            />
          </Box>

          <Typography
            sx={{ fontSize: 12, maxWidth: 360, textAlign: "center" }}
            color="text.secondary"
            gutterBottom
          >
            Using more words for your passphrase will make your secrets safer
            but be sure you can remember it!
          </Typography>
        </Stack>
      </Box>
      <Divider />
    </>
  );
}

interface DicewareProps {
  onGenerate: (passphrase: string) => void;
}

export default function Diceware(props: DicewareProps) {
  const { onGenerate } = props;
  const [passphrase, setPassphrase] = useState(null);
  const [bits, setBits] = useState(null);
  const [words, setWords] = useState(6);
  const [wordsVisible, setWordsVisible] = useState(false);

  const generate = async () => {
    const [passphrase, bits] = await generatePassphrase(words);
    setPassphrase(passphrase);
    setBits(Math.round(bits));
    onGenerate(passphrase);
  };

  const onChange = (words: number) => setWords(words);
  const onChangeCommitted = () => generate();

  useEffect(() => {
    generate();
  }, []);

  if (!passphrase) {
    return null;
  }

  return (
    <Card variant="outlined" sx={{ backgroundColor: "transparent" }}>
      <CardContent>
        <Box sx={{ marginBottom: 1 }}>
          <Stack
            direction="row"
            sx={{ width: "100%", alignItems: "flex-end" }}
            justifyContent="space-between"
          >
            <Stack direction="row" spacing={2}>
              <Tooltip title="Increase number of words">
                <ToggleButton
                  selected={wordsVisible}
                  onClick={() => setWordsVisible(!wordsVisible)}
                  aria-label="word count"
                  component="span"
                  value="words"
                >
                  <NumbersIcon />
                </ToggleButton>
              </Tooltip>
              <Stack>
                <Typography>Passphrase</Typography>
                <Typography
                  sx={{ fontSize: 12 }}
                  color="text.secondary"
                  gutterBottom
                >
                  {words} words, {bits} bit entropy
                </Typography>
              </Stack>
            </Stack>
            <Tooltip title="Generate a new passphrase">
              <IconButton
                onClick={generate}
                aria-label="refresh"
                sx={{ width: 36, height: 36 }}
              >
                <RefreshIcon />
              </IconButton>
            </Tooltip>
          </Stack>
        </Box>

        <Divider />

        {wordsVisible && (
          <WordCount
            words={words}
            onChange={onChange}
            onChangeCommitted={onChangeCommitted}
          />
        )}

        <Box sx={{ m: 2, marginBottom: 0 }}>
          <Typography
            sx={{ fontSize: 24, textAlign: "center" }}
            color="text.secondary"
          >
            {passphrase}
          </Typography>
        </Box>
      </CardContent>
    </Card>
  );
}
