#![no_std]
#![forbid(unsafe_code)]

//! Narrow capability contracts shared by replacement-firmware targets.
//!
//! These traits describe useful operations rather than registers or device
//! families. Target crates own MMIO, descriptor encoding, cache maintenance,
//! and interrupt routing below this boundary.

pub use mycelium_network_types::LinkState;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PacketLayer {
    EthernetFrame,
    ApplicationDatagram,
}

pub trait PacketRx {
    type Error;

    /// Receives one complete link-layer frame without blocking.
    fn try_receive(&mut self, output: &mut [u8]) -> Result<Option<usize>, Self::Error>;
}

pub trait PacketTx {
    type Error;

    /// Queues one complete link-layer frame without blocking.
    fn try_transmit(&mut self, frame: &[u8]) -> Result<(), Self::Error>;
}

pub trait PacketIo: PacketRx + PacketTx<Error = <Self as PacketRx>::Error> {
    fn packet_layer(&self) -> PacketLayer;
    fn link_state(&self) -> LinkState;
    fn maximum_frame_size(&self) -> usize;
}

pub trait InterruptSource {
    type Mask: Copy;

    fn pending(&self) -> Self::Mask;
    fn acknowledge(&mut self, mask: Self::Mask);
}

pub trait MonotonicClock {
    type Instant: Copy + Ord;

    fn now(&self) -> Self::Instant;
}

pub trait Console {
    type Error;

    fn try_read(&mut self) -> Result<Option<u8>, Self::Error>;
    fn write_all(&mut self, bytes: &[u8]) -> Result<(), Self::Error>;
}

pub trait Reset {
    fn reset(&mut self) -> !;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StorageGeometry {
    pub capacity: u32,
    pub erase_size: u32,
    pub program_size: u32,
}

pub trait BlockStorage {
    type Error;

    fn geometry(&self) -> StorageGeometry;
    fn read(&self, offset: u32, output: &mut [u8]) -> Result<(), Self::Error>;
    fn erase(&mut self, offset: u32, length: u32) -> Result<(), Self::Error>;
    fn program(&mut self, offset: u32, data: &[u8]) -> Result<(), Self::Error>;
}

pub trait ConfigStore {
    type Error;

    fn load(&self, output: &mut [u8]) -> Result<Option<usize>, Self::Error>;
    fn store(&mut self, value: &[u8]) -> Result<(), Self::Error>;
}

pub trait MidiRx {
    type Error;
    fn try_receive_midi(&mut self, output: &mut [u8]) -> Result<Option<usize>, Self::Error>;
}

pub trait MidiTx {
    type Error;
    fn try_transmit_midi(&mut self, message: &[u8]) -> Result<(), Self::Error>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ControlId(pub u16);

/// Device-neutral value produced by a physical control surface.
///
/// Target HALs own matrix scanning, debouncing, ADC scaling, and encoder
/// decoding. Policy above the HAL decides whether a value becomes MIDI, a
/// sequencer command, a management action, or something else.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ControlValue {
    Released,
    Pressed,
    /// Absolute position or strike velocity, normalized to the full `u16` range.
    Absolute(u16),
    /// Pressure measured after the initial key strike. Keeping this distinct
    /// preserves velocity versus aftertouch semantics above the HAL.
    Pressure(u16),
    /// Signed movement from an endless encoder or jog wheel.
    Relative(i16),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SurfaceEvent {
    pub control: ControlId,
    pub value: ControlValue,
}

pub trait SurfaceInput {
    type Error;

    /// Returns one debounced, normalized event without blocking.
    fn try_receive_control(&mut self) -> Result<Option<SurfaceEvent>, Self::Error>;
}

/// Reusable state machine for velocity-sensitive keybeds with two contacts per
/// key. Board adapters provide contact levels and a monotonically wrapping
/// tick; the scanner owns no GPIO, timer, MIDI, or allocation policy.
pub mod keybed {
    use super::{ControlId, ControlValue, SurfaceEvent};

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum KeyState {
        Open,
        FirstContact { at: u32 },
        Down,
    }

    pub trait VelocityCurve {
        fn velocity(&self, contact_ticks: u32) -> u16;
    }

    /// One integer segment recovered from a keyboard's velocity mapping.
    /// `slope_numerator * ticks / slope_denominator - offset` is evaluated
    /// with signed, truncating division and clamped to the segment's endpoint
    /// velocities. The values are in MIDI's 1..=127 domain; the curve scales
    /// them to the HAL's normalized 16-bit event domain.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct VelocitySegment {
        pub start_ticks: u32,
        pub start_velocity: u8,
        pub end_ticks: u32,
        pub end_velocity: u8,
        pub slope_numerator: i32,
        pub slope_denominator: i32,
        pub offset: i32,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct Piecewise7BitVelocityCurve<const SEGMENTS: usize> {
        segments: [VelocitySegment; SEGMENTS],
    }

    impl<const SEGMENTS: usize> Piecewise7BitVelocityCurve<SEGMENTS> {
        pub const fn new(segments: [VelocitySegment; SEGMENTS]) -> Self {
            Self { segments }
        }

        pub const fn segments(&self) -> &[VelocitySegment; SEGMENTS] {
            &self.segments
        }

        fn velocity_7bit(&self, contact_ticks: u32) -> u8 {
            let Some(segment) = self
                .segments
                .iter()
                .find(|segment| contact_ticks <= segment.end_ticks)
                .or_else(|| self.segments.last())
            else {
                return 1;
            };
            if segment.slope_denominator == 0 {
                return segment.end_velocity.max(1);
            }
            let calculated = i64::from(segment.slope_numerator) * i64::from(contact_ticks)
                / i64::from(segment.slope_denominator)
                - i64::from(segment.offset);
            let lower = i64::from(segment.start_velocity.min(segment.end_velocity));
            let upper = i64::from(segment.start_velocity.max(segment.end_velocity));
            calculated.clamp(lower, upper).clamp(1, 127) as u8
        }
    }

    impl<const SEGMENTS: usize> VelocityCurve for Piecewise7BitVelocityCurve<SEGMENTS> {
        fn velocity(&self, contact_ticks: u32) -> u16 {
            let velocity = u32::from(self.velocity_7bit(contact_ticks));
            ((velocity * u32::from(u16::MAX)) / 127) as u16
        }
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct LinearVelocityCurve {
        fastest_ticks: u32,
        slowest_ticks: u32,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct InvalidVelocityWindow;

    impl LinearVelocityCurve {
        pub const fn new(
            fastest_ticks: u32,
            slowest_ticks: u32,
        ) -> Result<Self, InvalidVelocityWindow> {
            if fastest_ticks >= slowest_ticks {
                return Err(InvalidVelocityWindow);
            }
            Ok(Self {
                fastest_ticks,
                slowest_ticks,
            })
        }
    }

    impl VelocityCurve for LinearVelocityCurve {
        fn velocity(&self, contact_ticks: u32) -> u16 {
            if contact_ticks <= self.fastest_ticks {
                return u16::MAX;
            }
            if contact_ticks >= self.slowest_ticks {
                return 1;
            }
            let span = self.slowest_ticks - self.fastest_ticks;
            let position = contact_ticks - self.fastest_ticks;
            let fall = (u64::from(position) * u64::from(u16::MAX - 1)) / u64::from(span);
            u16::MAX - fall as u16
        }
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct DualContactKeybed<C, const KEYS: usize> {
        controls_start_at: u16,
        curve: C,
        keys: [KeyState; KEYS],
    }

    impl<C: VelocityCurve, const KEYS: usize> DualContactKeybed<C, KEYS> {
        pub const fn new(controls_start_at: u16, curve: C) -> Self {
            Self {
                controls_start_at,
                curve,
                keys: [KeyState::Open; KEYS],
            }
        }

        /// Incorporates one sampled contact pair. Timer wrap is intentional:
        /// elapsed time uses `wrapping_sub`, matching fixed-width MCU timers.
        pub fn update(
            &mut self,
            key: usize,
            first_closed: bool,
            second_closed: bool,
            now: u32,
        ) -> Option<SurfaceEvent> {
            let state = self.keys.get_mut(key)?;
            let key_offset = u16::try_from(key).ok()?;
            let control = ControlId(self.controls_start_at.checked_add(key_offset)?);
            match (*state, first_closed, second_closed) {
                (KeyState::Open, true, false) => {
                    *state = KeyState::FirstContact { at: now };
                    None
                }
                (KeyState::Open, true, true) => {
                    *state = KeyState::Down;
                    Some(SurfaceEvent {
                        control,
                        value: ControlValue::Absolute(self.curve.velocity(0)),
                    })
                }
                (KeyState::FirstContact { at }, true, true) => {
                    *state = KeyState::Down;
                    Some(SurfaceEvent {
                        control,
                        value: ControlValue::Absolute(self.curve.velocity(now.wrapping_sub(at))),
                    })
                }
                (KeyState::FirstContact { .. }, false, false) => {
                    *state = KeyState::Open;
                    None
                }
                (KeyState::Down, false, false) => {
                    *state = KeyState::Open;
                    Some(SurfaceEvent {
                        control,
                        value: ControlValue::Released,
                    })
                }
                _ => None,
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FeedbackValue {
    Off,
    Level(u8),
    Rgb { red: u8, green: u8, blue: u8 },
}

pub trait SurfaceFeedback {
    type Error;
    fn set_feedback(&mut self, control: ControlId, value: FeedbackValue)
        -> Result<(), Self::Error>;
}

/// Electrical format for a monophonic control-voltage gate output.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GateMode {
    /// Active-low short-to-ground trigger.
    STrigger,
    /// Active-high five-volt trigger.
    VTrigger5V,
    /// Active-high twelve-volt trigger.
    VTrigger12V,
}

/// Device-neutral gate capability. Board drivers own the circuitry-specific
/// GPIO levels needed to realize the requested electrical format.
pub trait GateOutput {
    type Error;

    fn configure_gate_mode(&mut self, mode: GateMode) -> Result<(), Self::Error>;
    fn set_gate(&mut self, active: bool) -> Result<(), Self::Error>;
}

/// Normalized unipolar analog output. Voltage range and conversion hardware
/// are board policy; callers provide only a full-scale `u16` value.
pub trait AnalogOutput {
    type Error;

    fn set_normalized(&mut self, value: u16) -> Result<(), Self::Error>;
}

pub trait MdioBus {
    type Error;

    fn read(&mut self, phy: u8, register: u8) -> Result<u16, Self::Error>;
    fn write(&mut self, phy: u8, register: u8, value: u16) -> Result<(), Self::Error>;
}

/// A temperature channel expressed in milli-degrees Celsius.
pub trait TemperatureSensor {
    type Error;

    fn read_millidegrees_celsius(&mut self) -> Result<i32, Self::Error>;
}

/// One independently controlled fan channel.
pub trait FanControl {
    type Error;

    fn set_duty_percent(&mut self, duty_percent: u8) -> Result<(), Self::Error>;
    fn tachometer_rpm(&mut self) -> Result<u32, Self::Error>;
}

pub trait Watchdog {
    type Error;

    fn pet(&mut self) -> Result<(), Self::Error>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostPowerState {
    Off,
    On,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostPowerAction {
    MomentaryPower,
    GracefulShutdown,
    ForceOff,
    Reset,
    PowerCycle,
}

/// Electrical host-control operations. State policy belongs above this trait.
pub trait HostPowerControl {
    type Error;

    fn state(&mut self) -> Result<HostPowerState, Self::Error>;
    fn perform(&mut self, action: HostPowerAction) -> Result<(), Self::Error>;
}

#[cfg(test)]
mod tests {
    use super::{
        keybed::{
            DualContactKeybed, LinearVelocityCurve, Piecewise7BitVelocityCurve, VelocityCurve,
            VelocitySegment,
        },
        ControlId, ControlValue, SurfaceEvent,
    };

    #[test]
    fn dual_contact_timing_produces_velocity_then_release() {
        let curve = LinearVelocityCurve::new(10, 110).unwrap();
        let mut keybed = DualContactKeybed::<_, 32>::new(0, curve);
        assert_eq!(keybed.update(7, true, false, 1_000), None);
        let strike = keybed.update(7, true, true, 1_060).unwrap();
        assert_eq!(strike.control, ControlId(7));
        assert!(matches!(strike.value, ControlValue::Absolute(velocity) if velocity > 1));
        assert_eq!(keybed.update(7, false, true, 1_070), None);
        assert_eq!(
            keybed.update(7, false, false, 1_080),
            Some(SurfaceEvent {
                control: ControlId(7),
                value: ControlValue::Released,
            })
        );
    }

    #[test]
    fn dual_contact_timing_handles_timer_wrap_and_never_emits_pressure() {
        let curve = LinearVelocityCurve::new(1, 100).unwrap();
        let mut keybed = DualContactKeybed::<_, 1>::new(12, curve);
        assert_eq!(keybed.update(0, true, false, u32::MAX - 4), None);
        let strike = keybed.update(0, true, true, 5).unwrap();
        assert_eq!(strike.control, ControlId(12));
        assert!(matches!(strike.value, ControlValue::Absolute(_)));
    }

    #[test]
    fn piecewise_curve_uses_firmware_style_integer_math_and_normalizes() {
        let curve = Piecewise7BitVelocityCurve::new([
            VelocitySegment {
                start_ticks: 0,
                start_velocity: 127,
                end_ticks: 10,
                end_velocity: 127,
                slope_numerator: 0,
                slope_denominator: 1,
                offset: -127,
            },
            VelocitySegment {
                start_ticks: 10,
                start_velocity: 127,
                end_ticks: 50,
                end_velocity: 110,
                slope_numerator: -17,
                slope_denominator: 40,
                offset: -125,
            },
        ]);
        assert_eq!(curve.velocity(5), u16::MAX);
        assert_eq!(curve.velocity(30), (113 * u32::from(u16::MAX) / 127) as u16);
        assert_eq!(
            curve.velocity(500),
            (110 * u32::from(u16::MAX) / 127) as u16
        );
    }
}
