import { describe, expect, it, vi } from 'vitest'
import { mount } from '@vue/test-utils'
import ModelPlazaContent from '../ModelPlazaContent.vue'
import PlazaFilterBar from '../PlazaFilterBar.vue'
import type { ModelPlazaGroup, ModelPlazaResponse, PlazaModel } from '@/api/modelPlaza'

vi.mock('@/stores/auth', () => ({ useAuthStore: () => ({ isAuthenticated: false }) }))
vi.mock('vue-i18n', async (importOriginal) => ({
  ...await importOriginal<typeof import('vue-i18n')>(),
  useI18n: () => ({ t: (key: string) => key })
}))

function model(name: string, platform = 'openai', mode: 'token' | 'image' = 'token'): PlazaModel {
  return {
    name,
    platform,
    pricing: {
      billing_mode: mode,
      input_price: 5e-6,
      output_price: 10e-6,
      cache_write_price: null,
      cache_read_price: 1.25e-6,
      image_input_price: null,
      image_output_price: null,
      per_request_price: null,
      intervals: []
    },
    official_pricing: null
  }
}

function group(id: number, name: string, models: PlazaModel[], overrides: Partial<ModelPlazaGroup> = {}): ModelPlazaGroup {
  return {
    id, name, models,
    description: '',
    platform: 'openai',
    subscription_type: 'standard',
    rate_multiplier: 0.35,
    peak_rate_enabled: false,
    peak_start: '',
    peak_end: '',
    peak_rate_multiplier: 1,
    is_exclusive: false,
    image_rate_independent: true,
    image_rate_multiplier: 0.6,
    video_rate_independent: false,
    video_rate_multiplier: 1,
    long_context_pricing_enabled: true,
    ...overrides
  }
}

function catalogue(): ModelPlazaResponse {
  return { description: '', groups: [
    group(5, 'Mixed group', [
      model('gpt-5.6-sol'), model('gpt-image-1'), model('gpt-image-1.5'),
      model('gpt-image-2'), model('gpt-image-2.5-flare'), model('gpt-image-2.5-sunburst'),
      model('custom-painting', 'openai', 'image')
    ], { user_rate_multiplier: 0.2 }),
    group(8, 'Chat only', [model('claude-sonnet', 'anthropic')], { platform: 'anthropic', rate_multiplier: 0.7 }),
    group(11, 'Image only', [model('gpt-image-2')], { rate_multiplier: 0.09 })
  ] }
}

function mountContent(response = catalogue()) {
  return mount(ModelPlazaContent, {
    props: { response, loading: false },
    global: { stubs: {
      Icon: true,
      PlatformIcon: true,
      PlazaGroupSection: {
        name: 'PlazaGroupSection',
        props: ['group'],
        template: '<article><span v-for="model in group.models" :key="model.name">{{ model.name }}</span></article>'
      }
    } }
  })
}

async function click(wrapper: ReturnType<typeof mountContent>, label: string) {
  const button = wrapper.findAll('button').find(button => button.text() === label)
  expect(button, label + ' button').toBeDefined()
  await button!.trigger('click')
}

describe('ModelPlazaContent model categories', () => {
  it('separates token-billed GPT images and image aliases while preserving group prices and IDs', () => {
    const response = catalogue()
    const original = structuredClone(response)
    const wrapper = mountContent(response)
    const chat = wrapper.get('[data-testid="plaza-chat-models"]')
    const images = wrapper.get('[data-testid="plaza-image-models"]')
    expect(chat.text()).toContain('gpt-5.6-sol')
    expect(chat.text()).not.toContain('gpt-image')
    expect(images.text()).not.toContain('gpt-5.6-sol')
    expect(images.text()).toContain('gpt-image-2.5-sunburst')
    expect(images.text()).toContain('custom-painting')
    const imageGroup = images.findAllComponents({ name: 'PlazaGroupSection' })
      .find((section) => section.props('group').id === 5)!.props('group') as ModelPlazaGroup
    expect(imageGroup).toMatchObject({ id: 5, rate_multiplier: 0.35, user_rate_multiplier: 0.2, image_rate_independent: true, image_rate_multiplier: 0.6 })
    expect(imageGroup.models[0].pricing).toStrictEqual(response.groups[0].models[1].pricing)
    expect(response).toEqual(original)
  })

  it('combines image mode with model search and group selection', async () => {
    const wrapper = mountContent()
    await click(wrapper, 'modelPlaza.types.image')
    expect(wrapper.find('[data-testid="plaza-chat-models"]').exists()).toBe(false)
    expect(wrapper.get('[data-testid="plaza-image-models"]').text()).toContain('gpt-image-2')
    expect(wrapper.findComponent(PlazaFilterBar).props('groups').map((g: { id: number }) => g.id)).toEqual([5, 11])
    await click(wrapper, 'Image only')
    await wrapper.get('input').setValue('gpt-image-2')
    expect(wrapper.findAllComponents({ name: 'PlazaGroupSection' })).toHaveLength(1)
    expect(wrapper.findComponent({ name: 'PlazaGroupSection' }).props('group').id).toBe(11)
    await wrapper.get('input').setValue('does-not-exist')
    expect(wrapper.text()).toContain('modelPlaza.noSearchResult')
    expect(wrapper.find('[data-testid="plaza-image-models"]').exists()).toBe(false)
  })

  it('clears incompatible group and rate filters when switching from chat to GPT images', async () => {
    const wrapper = mountContent()
    await click(wrapper, 'Chat only')
    await click(wrapper, '0.7x')
    await click(wrapper, 'modelPlaza.types.image')
    const filters = wrapper.findComponent(PlazaFilterBar)
    expect(filters.props('groupId')).toBe('all')
    expect(filters.props('rate')).toBe('all')
    expect(wrapper.findAllComponents({ name: 'PlazaGroupSection' })).toHaveLength(2)
    await click(wrapper, 'modelPlaza.types.chat')
    expect(wrapper.find('[data-testid="plaza-image-models"]').exists()).toBe(false)
    expect(wrapper.get('[data-testid="plaza-chat-models"]').text()).not.toContain('gpt-image')
  })
})
