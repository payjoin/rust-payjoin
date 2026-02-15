import { createRequire } from "module";
import { fileURLToPath } from "url";
import { dirname, join } from "path";
import { existsSync, readFileSync } from "fs";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const require = createRequire(import.meta.url);

const { platform, arch } = process;

let nativeBinding = null;
let localFileExisted = false;
let loadError = null;

function isMusl() {
    if (!process.report || typeof process.report.getReport !== "function") {
        try {
            const { execSync } = require("child_process");
            const lddPath = execSync("which ldd").toString().trim();
            return readFileSync(lddPath, "utf8").includes("musl");
        } catch (e) {
            return true;
        }
    } else {
        const { glibcVersionRuntime } = process.report.getReport().header;
        return !glibcVersionRuntime;
    }
}

switch (platform) {
    case "darwin":
        switch (arch) {
            case "x64":
            case "arm64":
                localFileExisted = existsSync(
                    join(__dirname, "payjoin-test-utils-napi.node"),
                );
                try {
                    if (localFileExisted) {
                        nativeBinding = require("./payjoin-test-utils-napi.node");
                    }
                } catch (e) {
                    loadError = e;
                }
                break;
            default:
                throw new Error(`Unsupported architecture on macOS: ${arch}`);
        }
        break;
    case "linux":
        switch (arch) {
            case "x64":
            case "arm64":
                localFileExisted = existsSync(
                    join(__dirname, "payjoin-test-utils-napi.node"),
                );
                try {
                    if (localFileExisted) {
                        nativeBinding = require("./payjoin-test-utils-napi.node");
                    }
                } catch (e) {
                    loadError = e;
                }
                break;
            default:
                throw new Error(`Unsupported architecture on Linux: ${arch}`);
        }
        break;
    default:
        throw new Error(`Unsupported OS: ${platform}, architecture: ${arch}`);
}

if (!nativeBinding) {
    if (loadError) {
        throw loadError;
    }
    throw new Error(`Failed to load native binding`);
}

export const {
    BitcoindEnv,
    BitcoindInstance,
    RpcClient,
    TestServices,
    initBitcoindSenderReceiver,
    originalPsbt,
} = nativeBinding;
