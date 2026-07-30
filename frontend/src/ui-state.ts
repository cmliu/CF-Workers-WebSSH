export type ConnectionControlState = 'idle' | 'connecting' | 'connected' | 'disconnecting' | 'error';
export type ConnectionControlAction = 'connect' | 'cancel' | 'disconnect' | 'disconnecting';

export interface ConnectionControlView {
  action: ConnectionControlAction;
  danger: boolean;
  disabled: boolean;
}

export function resolveConnectionControl(state: ConnectionControlState, passwordLoading: boolean): ConnectionControlView {
  if (state === 'connecting') return { action: 'cancel', danger: true, disabled: false };
  if (state === 'connected') return { action: 'disconnect', danger: true, disabled: false };
  if (state === 'disconnecting') return { action: 'disconnecting', danger: true, disabled: true };
  return { action: 'connect', danger: false, disabled: passwordLoading };
}

export interface ConnectionPanelView {
  expanded: boolean;
  drawerOpen: boolean;
  scrimVisible: boolean;
}

export function resolveConnectionPanel(open: boolean): ConnectionPanelView {
  return {
    expanded: open,
    drawerOpen: open,
    scrimVisible: open,
  };
}
