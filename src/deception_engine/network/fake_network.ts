export type FakeNetworkResponse = {
  status: number
  message: string
}

export function simulateNetworkRequest(url: string): FakeNetworkResponse {

  return {
    status: 200,
    message: `Connected to ${url}`,
  }

}
