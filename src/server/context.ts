import { mkdir } from "node:fs/promises";
import type { VestigeConfig } from "../config/config.js";
import { TargetRegistry } from "../services/targetRegistry.js";
import { ProviderRegistry } from "../services/providerRegistry.js";
import { EvidenceStore } from "../services/evidenceStore.js";
import { JobManager } from "../services/jobManager.js";
import { AnalysisService } from "../services/analysisService.js";
import { JavaScriptProvider } from "../providers/javascript/provider.js";
import { NativeProvider } from "../providers/native/provider.js";
import { GhidraProvider } from "../providers/ghidra/provider.js";
import { createLogger, type Logger } from "../util/log.js";
import { Workspace } from "../security/workspace.js";
import { PRODUCT } from "../version.js";

/**
 * Composition root. The only place that instantiates concrete providers;
 * application services depend on interfaces exclusively. Provider cleanup
 * is centralized here (in-process providers need none; external-tool
 * providers use the bounded runner which owns its child processes).
 */
export interface Platform {
  config: VestigeConfig;
  log: Logger;
  targets: TargetRegistry;
  providers: ProviderRegistry;
  store: EvidenceStore;
  jobs: JobManager;
  analysis: AnalysisService;
  workspace: Workspace;
  close(): Promise<void>;
}

export const createPlatform = async (
  config: VestigeConfig,
  log?: Logger,
): Promise<Platform> => {
  await mkdir(config.dataDir, { recursive: true });
  await mkdir(config.workDir, { recursive: true });
  const logger = log ?? createLogger(config.logLevel);
  const workspace = await Workspace.create(config.workDir);

  const targets = new TargetRegistry(config.dataDir, {
    allowedRoots: config.allowedRoots,
  });
  const providers = new ProviderRegistry();
  providers.register(new JavaScriptProvider());
  providers.register(new NativeProvider());
  providers.register(new GhidraProvider(config.ghidraInstallDir));
  const store = new EvidenceStore(config.dataDir);
  const jobs = new JobManager();
  const analysis = new AnalysisService(
    targets,
    providers,
    store,
    jobs,
    config.dataDir,
  );

  logger.info("vestige platform initialized", {
    dataDir: config.dataDir,
    providers: providers.list().map((p) => p.descriptor.id),
  });

  return {
    config,
    log: logger,
    targets,
    providers,
    store,
    jobs,
    analysis,
    workspace,
    close: async () => {
      await workspace.cleanup();
      logger.info(`${PRODUCT.name} platform closed`);
    },
  };
};
