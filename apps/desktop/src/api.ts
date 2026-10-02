import { invoke, isTauri } from '@tauri-apps/api/core';
import type { Action, Status } from './types';
export const native = isTauri();
export const getStatus = () => invoke<Status>('service_status');
export const sendAction = (action: Action) => invoke<void>('service_action', { action });
