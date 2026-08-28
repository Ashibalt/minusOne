import { rm } from "node:fs/promises";

/**
 * Remove a workspace temp root, retrying on Windows EBUSY/EPERM. Defender (or
 * another filter) can briefly hold a handle on freshly-written temp files
 * right after a live run writes them; without a retry the suite turns red
 * intermittently even though every assertion passed.
 */
export async function rmRoot(root) {
  for (let attempt = 0; attempt < 6; attempt++) {
    try {
      await rm(root, { recursive: true, force: true });
      return;
    } catch (error) {
      const code = error?.code;
      if (code !== "EBUSY" && code !== "EPERM" && code !== "ENOTEMPTY") throw error;
      await new Promise((resolve) => setTimeout(resolve, 250));
    }
  }
}
