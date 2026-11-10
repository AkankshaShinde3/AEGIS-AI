import axios from 'axios'

const api = axios.create({ baseURL: '/api' })

export const getDashboard = () => api.get('/dashboard').then(r => r.data)
export const getTraffic = (limit = 200) => api.get('/traffic', { params: { limit } }).then(r => r.data)
export const simulateTraffic = () => api.post('/simulate').then(r => r.data)
export const uploadCsv = (file) => {
  const form = new FormData()
  form.append('file', file)
  return api.post('/upload', form).then(r => r.data)
}
export const getAlerts = (status) =>
  api.get('/alerts', { params: status ? { status } : {} }).then(r => r.data)
export const updateAlert = (id, data) =>
  api.patch(`/alerts/${id}`, data).then(r => r.data)
