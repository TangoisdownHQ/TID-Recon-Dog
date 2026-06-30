import { AttackerProfile, AttackerServiceMemory } from "../deception_engine/state/attacker_memory.js";
import { DecoyPersona } from "../profiles/personaLibrary.js";

export type ResponderContext = {
  attacker: AttackerProfile;
  serviceMemory: AttackerServiceMemory;
  persona: DecoyPersona;
};
