import { useEffect, useState } from "react";
import useSWR from "swr";

const fetcher = (url: string) => fetch(url).then((r) => r.json());

export function useScanProgress(scanId: string) {
  const apiBase = process.env.NEXT_PUBLIC_API_URL;
  const isComplete = (status: string) => ["complete", "failed"].includes(status);

  const { data, error } = useSWR(
    `${apiBase}/api/v1/scan/${scanId}`,
    fetcher,
    {
      refreshInterval: (data) => (data && isComplete(data.status) ? 0 : 2000),
    }
  );

  return {
    scan: data,
    isLoading: !error && !data,
    isComplete: data ? isComplete(data.status) : false,
    error,
  };
}
