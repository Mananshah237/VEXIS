import useSWR from "swr";

const fetcher = (url: string) => fetch(url).then((r) => r.json());

export function useFindings(scanId: string, params?: { severity?: string; vuln_class?: string; page?: number }) {
  const apiBase = process.env.NEXT_PUBLIC_API_URL;
  const query = new URLSearchParams();
  if (params?.severity) query.set("severity", params.severity);
  if (params?.vuln_class) query.set("vuln_class", params.vuln_class);
  if (params?.page) query.set("page", String(params.page));

  const url = `${apiBase}/api/v1/scan/${scanId}/findings?${query.toString()}`;
  const { data, error, mutate } = useSWR(url, fetcher);

  return {
    findings: data?.findings ?? [],
    total: data?.total ?? 0,
    isLoading: !error && !data,
    error,
    mutate,
  };
}
