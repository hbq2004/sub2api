import type { PlazaModel } from '@/api/modelPlaza'

export type PlazaModelType = 'all' | 'chat' | 'image'

export function isGPTImageModel(model: PlazaModel): boolean {
  return model.platform === 'openai' && (
    /^(?:gpt-image|dall-e)(?:-|$)/i.test(model.name.trim()) ||
    model.pricing?.billing_mode === 'image'
  )
}
