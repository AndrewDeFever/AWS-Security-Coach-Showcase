export type ReportDeliveryModel = "managed" | "self-service";
export type ReportDocumentType = "management" | "engineering";

export type ReportDocumentRoute = {
  scanId: string;
  deliveryModel: ReportDeliveryModel;
  documentType: ReportDocumentType;
};

export function reportRoute(scanId: string, deliveryModel: ReportDeliveryModel, documentType: ReportDocumentType): string {
  return `#/reports/${encodeURIComponent(scanId)}/${deliveryModel}/${documentType}`;
}

export function parseReportRoute(hash: string): ReportDocumentRoute | null {
  const modern = hash.match(/^#\/reports\/([^/]+)\/(managed|self-service)\/(management|engineering)$/i);
  const legacy = hash.match(/^#\/reports\/([^/]+)\/(management|engineering)$/i);
  const match = modern ?? legacy;
  if (!match) return null;

  try {
    const scanId = decodeURIComponent(match[1]).trim();
    if (!scanId || !/^[A-Za-z0-9-]+$/.test(scanId)) return null;

    if (modern) {
      return {
        scanId,
        deliveryModel: match[2].toLowerCase() as ReportDeliveryModel,
        documentType: match[3].toLowerCase() as ReportDocumentType,
      };
    }

    return {
      scanId,
      deliveryModel: "managed",
      documentType: match[2].toLowerCase() as ReportDocumentType,
    };
  } catch {
    return null;
  }
}
