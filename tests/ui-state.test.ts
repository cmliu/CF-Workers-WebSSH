import { describe, expect, it } from 'vitest';
import { resolveConnectionControl, resolveConnectionPanel } from '../frontend/src/ui-state';

describe('connection controls', () => {
  it('uses one button for connect, cancel, and disconnect', () => {
    expect(resolveConnectionControl('idle', false)).toEqual({ action: 'connect', danger: false, disabled: false });
    expect(resolveConnectionControl('error', true)).toEqual({ action: 'connect', danger: false, disabled: true });
    expect(resolveConnectionControl('connecting', true)).toEqual({ action: 'cancel', danger: true, disabled: false });
    expect(resolveConnectionControl('connected', true)).toEqual({ action: 'disconnect', danger: true, disabled: false });
    expect(resolveConnectionControl('disconnecting', true)).toEqual({ action: 'disconnecting', danger: true, disabled: true });
  });
});

describe('connection panel', () => {
  it('supports desktop collapse and mobile drawer states', () => {
    expect(resolveConnectionPanel(true, false)).toEqual({
      expanded: true,
      drawerOpen: false,
      desktopCollapsed: false,
      scrimVisible: false,
    });
    expect(resolveConnectionPanel(false, false)).toEqual({
      expanded: false,
      drawerOpen: false,
      desktopCollapsed: true,
      scrimVisible: false,
    });
    expect(resolveConnectionPanel(true, true)).toEqual({
      expanded: true,
      drawerOpen: true,
      desktopCollapsed: false,
      scrimVisible: true,
    });
    expect(resolveConnectionPanel(false, true)).toEqual({
      expanded: false,
      drawerOpen: false,
      desktopCollapsed: false,
      scrimVisible: false,
    });
  });
});
