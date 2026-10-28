import type {
  AnalysisProvider,
  Availability,
  CapabilityDescriptor,
  ProviderDescriptor,
} from "../providers/types.js";

/**
 * Provider registry: registration-order-independent selection, duplicate
 * detection, and aggregated availability diagnostics. Providers own their
 * cleanup (none needed for in-process providers; external-tool providers
 * manage their own processes via the bounded runner).
 */
export class ProviderRegistry {
  private readonly providers = new Map<string, AnalysisProvider>();

  register(provider: AnalysisProvider): void {
    const { id } = provider.descriptor;
    if (this.providers.has(id)) {
      throw new Error(`provider '${id}' is already registered`);
    }
    this.providers.set(id, provider);
  }

  list(): AnalysisProvider[] {
    return [...this.providers.values()].sort((a, b) =>
      a.descriptor.id < b.descriptor.id ? -1 : 1,
    );
  }

  get(id: string): AnalysisProvider | undefined {
    return this.providers.get(id);
  }

  /** Providers that support the given artifact format. */
  supporting(artifact: { format: string }): AnalysisProvider[] {
    return this.list().filter((p) =>
      p.supports({ format: artifact.format }),
    );
  }

  async availability(): Promise<
    Array<{ descriptor: ProviderDescriptor; availability: Availability }>
  > {
    return Promise.all(
      this.list().map(async (p) => ({
        descriptor: p.descriptor,
        availability: await p.checkAvailability(),
      })),
    );
  }

  capabilities(): Array<{
    provider: ProviderDescriptor;
    capabilities: CapabilityDescriptor[];
  }> {
    return this.list().map((p) => ({
      provider: p.descriptor,
      capabilities: p.capabilities(),
    }));
  }
}
