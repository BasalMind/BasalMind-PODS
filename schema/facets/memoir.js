// Facet `memoir` v0 -- PLACEHOLDER. Reserves the name and a minimal shape only;
// the real memoir design is a later stage. Not deployable: the manifest flags it
// (status "placeholder", deployable false) so a pod never installs it.
import { z } from "zod/mini";
import { Txt } from "../lib.js";

export const Chapter = z.strictObject({
  title: Txt(120),
  body: z.string().check(z.maxLength(20000)),
});

export const facet = {
  name: "memoir",
  version: 0,
  status: "placeholder",
  deployable: false,
  lists: { chapters: Chapter },
};
