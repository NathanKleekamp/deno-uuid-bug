import { v4 } from "https://deno.land/std@0.52.0/uuid/mod.ts";

const uuid = v4.generate();

console.log("uuid", uuid);
