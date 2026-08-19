//! Installing and removing the periodic sync (DESIGN.md §8).
//!
//! `anago sync --install-timer` has to answer three questions before it
//! touches anything: what schedules things on this machine, which
//! `device.json` the schedule should point at, and whether that file is
//! even there. All three are settled in [`plan`], which is pure — what
//! gets written is a value long before anything is written.
//!
//! Two machines get a schedule: systemd's timer pair and macOS's
//! LaunchDaemon. **A third gets nothing, on purpose.** Where neither
//! exists there is no honest install to perform, so the command prints
//! the crontab line a person can add themselves and stops — the same
//! answer `server init --no-systemd` gives, and for the same reason: a
//! timer that was never installed is better than one that was faked.

use std::fmt;
use std::io;
use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::diagnostics::Target;
use crate::wg::Cmd;
use crate::{launchd, systemd};

/// What schedules things on this machine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scheduler {
    Systemd,
    Launchd,
    /// A container, a non-systemd Linux, anything else.
    Neither,
}

/// Which one to use, given what is on the machine.
///
/// systemd first. The two are not expected to coexist, and asking in
/// this order means a Linux box that happens to have a
/// `/Library/LaunchDaemons` directory still gets the scheduler it
/// actually runs.
pub fn scheduler(systemd_running: bool, launch_daemons: bool) -> Scheduler {
    match (systemd_running, launch_daemons) {
        (true, _) => Scheduler::Systemd,
        (false, true) => Scheduler::Launchd,
        (false, false) => Scheduler::Neither,
    }
}

/// [`scheduler`] against this machine.
///
/// launchd is asked for as "macOS **and** the directory is there"
/// rather than either alone: the target says what kind of machine this
/// is, and the directory says the system daemons are where they are
/// supposed to be.
pub fn scheduler_here() -> Scheduler {
    scheduler(
        systemd::is_available(),
        cfg!(target_os = "macos") && Path::new(launchd::DAEMON_DIR).is_dir(),
    )
}

/// Everything the install needs to know, resolved by the caller.
///
/// `device_file` is resolved **at install time** and written into the
/// schedule (§8). That is the whole reason a timer can exist: the unit
/// runs as root outside any session, so §9's `XDG_CONFIG_HOME`/
/// `SUDO_UID` rules cannot be applied then — but they can be applied
/// now, while `sudo anago sync --install-timer` still has the invoking
/// user in its environment.
#[derive(Debug, Clone, Copy)]
pub struct Setup<'a> {
    pub exec: &'a Path,
    pub device_file: &'a Path,
    pub wg_config: &'a Path,
    pub interval: Duration,
    pub unit_dir: &'a Path,
    pub daemon_dir: &'a Path,
}

/// A file the install is going to write.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Written {
    pub path: PathBuf,
    pub text: String,
}

/// What `--install-timer` will do, decided before it does any of it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Plan {
    Systemd {
        service: Written,
        timer: Written,
    },
    Launchd {
        plist: Written,
    },
    /// Nothing to install here. The line is for the person to add.
    ByHand {
        line: String,
    },
}

/// What is already on the machine, looked up by the caller.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Existing {
    /// Is there a `device.json` at the resolved path?
    pub joined: bool,
    /// A schedule already installed, and where. Empty means none.
    pub schedule: Vec<PathBuf>,
}

/// Decides the whole install.
///
/// Nothing here touches the filesystem; what it needed to know about
/// the machine arrived in `have`.
///
/// **A schedule pointing at nothing is worse than no schedule.** It
/// fails every five minutes in a log nobody reads while the person
/// believes their device is syncing, so a missing device file stops the
/// install instead of producing one (§8). It is checked before the
/// platform, because "join first" is the answer on all three.
///
/// **An existing schedule is not replaced in place.** Overwriting one
/// means that a failure at the step after the write leaves neither the
/// old schedule nor the new one, and putting the old bytes back is not
/// enough — by then systemd has reloaded them, or launchd has taken the
/// new file. So the answer is the one `server init` gives to a hub that
/// already exists: stop, and name the command that clears the way.
/// Changing the period is uninstall then install, and both halves say
/// what they did.
pub fn plan(machine: Scheduler, have: &Existing, setup: &Setup) -> Result<Plan, TimerError> {
    if !have.joined {
        return Err(TimerError::NotJoined {
            device_file: setup.device_file.to_path_buf(),
        });
    }
    if !have.schedule.is_empty() {
        return Err(TimerError::AlreadyInstalled {
            files: have.schedule.clone(),
        });
    }
    match machine {
        Scheduler::Systemd => Ok(Plan::Systemd {
            service: Written {
                path: systemd::unit_path(setup.unit_dir, systemd::SYNC_SERVICE),
                text: systemd::sync_service_text(setup.exec, setup.device_file, setup.wg_config)?,
            },
            timer: Written {
                path: systemd::unit_path(setup.unit_dir, systemd::SYNC_TIMER),
                text: systemd::sync_timer_text(setup.interval),
            },
        }),
        Scheduler::Launchd => Ok(Plan::Launchd {
            plist: Written {
                path: launchd::plist_path(setup.daemon_dir),
                text: launchd::sync_plist(setup.exec, setup.device_file, setup.interval)?,
            },
        }),
        Scheduler::Neither => Ok(Plan::ByHand {
            line: crontab_line(setup.exec, setup.device_file, setup.interval)?,
        }),
    }
}

/// The five fields of a crontab line, for a period.
///
/// `None` when cron cannot say it. cron repeats on the clock rather
/// than on a stopwatch, so `*/7 * * * *` is not "every seven minutes" —
/// it is minutes 0, 7, … 56 and then a four-minute gap at the hour. A
/// period is expressible only when it divides the thing above it:
/// whole minutes that divide an hour, or whole hours that divide a day.
pub fn cron_schedule(interval: Duration) -> Option<String> {
    let seconds = interval.as_secs();
    if seconds == 0 || !seconds.is_multiple_of(60) {
        return None;
    }
    let minutes = seconds / 60;
    if minutes == 1 {
        return Some("* * * * *".to_string());
    }
    if minutes < 60 {
        return 60u64
            .is_multiple_of(minutes)
            .then(|| format!("*/{minutes} * * * *"));
    }
    if !minutes.is_multiple_of(60) {
        return None;
    }
    let hours = minutes / 60;
    match hours {
        1 => Some("0 * * * *".to_string()),
        24 => Some("0 0 * * *".to_string()),
        _ if hours < 24 && 24u64.is_multiple_of(hours) => Some(format!("0 */{hours} * * *")),
        _ => None,
    }
}

/// The command half of that line.
///
/// Two readers, and they do not agree about backslashes. cron reads the
/// line first, where an unescaped `%` **ends the command** and turns
/// the rest into standard input — a path holding one would silently
/// shorten the line into something that still runs. `\%` gets a percent
/// through. Then `/bin/sh` reads what is left, where a space splits one
/// path into two arguments unless it is quoted.
///
/// **A backslash already in the path is refused** ([`shell`]). cron's
/// escape pass consumes the character after a backslash, so a literal
/// one shifts which characters are consumed — `…/a\%b` rendered as
/// `…/a\\%b` has the first backslash eat the second, leaving the `%`
/// bare and the command cut in half. Getting that right means
/// depending on a parser this code cannot run, on a line that runs as
/// root, so it does not depend on it: with no backslash in the path,
/// every `\%` here is one this function put there.
pub fn crontab_command(exec: &Path, device_file: &Path) -> Result<String, TimerError> {
    let line = format!(
        "{} sync --quiet --config {}",
        shell(exec)?,
        shell(device_file)?
    );
    Ok(line.replace('%', "\\%"))
}

/// A whole crontab line.
pub fn crontab_line(
    exec: &Path,
    device_file: &Path,
    interval: Duration,
) -> Result<String, TimerError> {
    let schedule = cron_schedule(interval).ok_or(TimerError::NotCron { interval })?;
    Ok(format!(
        "{schedule} {}",
        crontab_command(exec, device_file)?
    ))
}

/// Renders a path as one shell word.
///
/// Single quotes, and only when the text needs them — a crontab is
/// something a person reads and edits, and quoting `/usr/local/bin/anago`
/// helps nobody. Inside single quotes every character is literal except
/// a single quote, which closes the run: `'\''` closes, escapes one,
/// and opens again.
///
/// Control characters are refused rather than escaped. A crontab is
/// read one line at a time, so a newline in a path would end the entry
/// — the same reason a systemd unit refuses one, and there is no
/// quoting here that survives it either.
///
/// A backslash is refused for cron's sake rather than the shell's — see
/// [`crontab_command`]. Only here: systemd and launchd take a path with
/// a backslash in it and this refusal would be untrue at their lines.
fn shell(path: &Path) -> Result<String, TimerError> {
    let Some(text) = path.to_str() else {
        return Err(TimerError::NotText(path.to_path_buf()));
    };
    if text.chars().any(char::is_control) {
        return Err(TimerError::NotOneLine(path.to_path_buf()));
    }
    if text.contains('\\') {
        return Err(TimerError::Backslash(path.to_path_buf()));
    }
    let plain = text
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || "/._-+,=:@".contains(c));
    if plain {
        return Ok(text.to_string());
    }
    Ok(format!("'{}'", text.replace('\'', "'\\''")))
}

/// What `--uninstall-timer` will take away.
///
/// It reads no device file: the names are fixed, so removal is the one
/// half of this that needs nothing but the platform (§8).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Removal {
    Systemd { service: PathBuf, timer: PathBuf },
    Launchd { plist: PathBuf },
    Neither,
}

impl Removal {
    /// Which scheduler this belongs to.
    pub fn scheduler(&self) -> Scheduler {
        match self {
            Removal::Systemd { .. } => Scheduler::Systemd,
            Removal::Launchd { .. } => Scheduler::Launchd,
            Removal::Neither => Scheduler::Neither,
        }
    }

    /// The files this kind of schedule occupies.
    ///
    /// One list, used twice: it is what `--uninstall-timer` takes away,
    /// and it is what `--install-timer` must not find already there.
    pub fn files(&self) -> Vec<&Path> {
        match self {
            Removal::Systemd { service, timer } => vec![service, timer],
            Removal::Launchd { plist } => vec![plist],
            Removal::Neither => Vec::new(),
        }
    }
}

pub fn removal(machine: Scheduler, unit_dir: &Path, daemon_dir: &Path) -> Removal {
    match machine {
        Scheduler::Systemd => Removal::Systemd {
            service: systemd::unit_path(unit_dir, systemd::SYNC_SERVICE),
            timer: systemd::unit_path(unit_dir, systemd::SYNC_TIMER),
        },
        Scheduler::Launchd => Removal::Launchd {
            plist: launchd::plist_path(daemon_dir),
        },
        Scheduler::Neither => Removal::Neither,
    }
}

/// What the install says when it is done.
///
/// Every branch names the device file, because the mistake this whole
/// path exists to avoid is a schedule that reads root's `device.json`
/// instead of the one somebody joined with (§8). And every branch says
/// how to check, because there is no `anago` command that reports
/// whether a timer is installed — the install output is the whole
/// surface (§8).
pub fn report(plan: &Plan, device_file: &Path) -> String {
    let device = device_file.display();
    match plan {
        Plan::Systemd { service, timer } => format!(
            "The sync timer is installed and running:\n     \
             {}\n     \
             {}\n\n     \
             It syncs {device}.\n     \
             `systemctl list-timers 'anago-sync*'` says when it next fires, and\n     \
             `{}` shows the file it reads.\n",
            service.path.display(),
            timer.path.display(),
            systemd::cat_sync_service().display()
        ),
        Plan::Launchd { plist } => format!(
            "The sync daemon is installed and running:\n     \
             {}\n\n     \
             It syncs {device}.\n     \
             Check it with `sudo launchctl print {}` —\n     \
             both the sudo and the `system/` are needed, because a plain\n     \
             `launchctl list` only looks at your own login session.\n\n     \
             Recent macOS lists it in System Settings, under Login Items &\n     \
             Extensions, where it can be switched off. An install that looks\n     \
             fine but never runs is usually that.\n",
            plist.path.display(),
            launchd::target()
        ),
        Plan::ByHand { line } => format!(
            "This machine has neither systemd nor launchd, so nothing was\n\
             installed — anago will not pretend to schedule something it cannot.\n\n     \
             Add this to root's crontab (`sudo crontab -e`):\n\n     \
             {line}\n\n     \
             It syncs {device}.\n     \
             `anago sync` by hand does the same work.\n"
        ),
    }
}

/// Whether the schedule is actually stopped now.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stopped {
    /// The stop worked.
    Gone,
    /// It was not loaded to begin with, so there was nothing to stop.
    NotLoaded,
    /// The stop did not work and it is still loaded.
    StillThere,
    /// The stop did not work and the check could not say either way.
    /// Not the same thing as [`Stopped::NotLoaded`], and reporting it
    /// as one would be claiming to have removed something that may
    /// still be running.
    Unknown,
}

/// Reads a stop attempt.
///
/// A failed `systemctl disable --now` or `launchctl bootout` is not
/// evidence of anything on its own: the usual cause is that nothing was
/// loaded, and the unusual one is that something is loaded and would
/// not stop. Deleting the files does not separate them — a LaunchDaemon
/// keeps running after its plist is gone, which is the whole reason
/// bootout exists.
///
/// So a failure is followed by a question with a yes-or-no answer
/// (`systemctl is-active`, `launchctl print`), and `still_there` is
/// what it said. `None` means the question itself could not be put,
/// which is not a "no".
pub fn stopped(stop_worked: bool, still_there: Option<bool>) -> Stopped {
    match (stop_worked, still_there) {
        (true, _) => Stopped::Gone,
        (false, Some(false)) => Stopped::NotLoaded,
        (false, Some(true)) => Stopped::StillThere,
        (false, None) => Stopped::Unknown,
    }
}

/// Reads the answer to "is it still there?".
///
/// A non-zero exit from `systemctl is-active` or `launchctl print` is
/// not the same as "it is gone". Both also fail when the manager cannot
/// be reached, when the caller is not allowed to ask, or when the IPC
/// underneath them breaks — and treating any of those as an absence
/// would report a schedule as removed while it is still running.
///
/// So only three answers are taken:
///
/// - exit 0 — it is there;
/// - a **state word** from systemd (`is-active` prints one on stdout,
///   and prints nothing at all when it could not ask), or a message
///   from launchctl that names the thing it could not find;
/// - anything else — no answer.
///
/// Recognising the absences by their wording is safe in the direction
/// that matters: a phrase this does not know becomes `None`, which is
/// the careful answer. The list can only ever forgive less than the
/// truth, never more.
pub fn still_there(machine: Scheduler, ok: bool, stdout: &str, stderr: &str) -> Option<bool> {
    if ok {
        return Some(true);
    }
    let absent = match machine {
        // `is-active` prints the state and exits non-zero for every
        // state but "active". An empty stdout means it never got as far
        // as asking — a bus it could not reach, most often.
        Scheduler::Systemd => matches!(stdout.trim(), "inactive" | "failed" | "unknown"),
        Scheduler::Launchd => {
            let said = stderr.to_ascii_lowercase();
            ["could not find service", "no such process", "no such file"]
                .iter()
                .any(|phrase| said.contains(phrase))
        }
        // Nothing was ever asked, because there is nothing to ask about.
        Scheduler::Neither => true,
    };
    absent.then_some(false)
}

/// What the removal says.
///
/// `gone` is what this run actually deleted, so "there was nothing
/// here" and "I took it away" are different sentences rather than the
/// same optimistic one.
pub fn removal_report(removal: &Removal, gone: &[PathBuf], stopped: Stopped) -> String {
    if let Removal::Neither = removal {
        // Never claim to have removed a crontab line: anago did not
        // write it, and it cannot see it.
        return "There is no sync timer to remove — this machine has neither systemd\n\
                nor launchd. If you added a crontab line by hand, take it out with\n\
                `sudo crontab -e`; anago never wrote one.\n"
            .to_string();
    }
    if gone.is_empty() {
        // Its file was already gone but it was still loaded — somebody
        // deleted the unit by hand and it kept running until now.
        if stopped == Stopped::Gone {
            return "There was no file left to remove, but the schedule was still\n\
                    loaded — it is stopped now. `anago sync` by hand still works.\n"
                .to_string();
        }
        return "No sync timer was installed here. Nothing to remove.\n".to_string();
    }
    let mut report = String::from("The sync timer is gone:\n");
    for path in gone {
        report.push_str(&format!("     {}\n", path.display()));
    }
    if stopped == Stopped::NotLoaded {
        report.push_str("     (It was not loaded, so there was nothing to stop.)\n");
    }
    report.push_str("     `anago sync` by hand still works.\n");
    report
}

/// One thing an install does.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Step {
    Write(Written),
    Delete(PathBuf),
    Run(Cmd),
}

impl Step {
    /// The step as a person would say it — for the one message that
    /// has to list steps that did not work.
    pub fn describe(&self) -> String {
        match self {
            Step::Write(file) => format!("write {}", file.path.display()),
            Step::Delete(path) => format!("remove {}", path.display()),
            Step::Run(cmd) => format!("run `{}`", cmd.display()),
        }
    }
}

/// Everything the install does, in order.
///
/// The reload comes between writing the units and enabling the timer
/// because `systemctl enable` resolves the unit through the manager,
/// which has not read it yet.
pub fn steps(plan: &Plan) -> Vec<Step> {
    match plan {
        Plan::Systemd { service, timer } => vec![
            Step::Write(service.clone()),
            Step::Write(timer.clone()),
            Step::Run(systemd::daemon_reload()),
            Step::Run(systemd::enable_sync_timer()),
        ],
        Plan::Launchd { plist } => vec![
            Step::Write(plist.clone()),
            Step::Run(launchd::bootstrap(&plist.path)),
        ],
        // Nothing was installed, so there is nothing to install.
        Plan::ByHand { .. } => Vec::new(),
    }
}

/// How to put the machine back, when the step at index `failed` did
/// not work and the ones before it did.
///
/// This is the whole reason [`plan`] refuses to install over an
/// existing schedule: with nothing there beforehand, "undo what this
/// run did" and "leave the machine as it was" are the same list, and
/// neither needs a copy of somebody else's file.
///
/// Three things get undone, in the reverse of the order they happened:
///
/// 1. **The activation.** A failed `enable --now` is not a no-op — it
///    can leave some of the symlinks it was making, and deleting the
///    unit file afterwards leaves those dangling. `disable --now`
///    first.
/// 2. **The files.** Both of them unconditionally: a write that failed
///    part-way still leaves a file, and `plan` guaranteed nothing was
///    there before, so anything at those paths is this run's.
/// 3. **The manager's idea of them.** Only when it had already been
///    told to look — otherwise it never knew, and there is nothing to
///    correct.
pub fn rewind(plan: &Plan, failed: usize) -> Vec<Step> {
    match plan {
        Plan::Systemd { service, timer } => {
            let mut back = Vec::new();
            if failed >= 3 {
                back.push(Step::Run(systemd::disable_sync_timer()));
            }
            back.push(Step::Delete(timer.path.clone()));
            back.push(Step::Delete(service.path.clone()));
            if failed >= 2 {
                back.push(Step::Run(systemd::daemon_reload()));
            }
            back
        }
        Plan::Launchd { plist } => {
            let mut back = Vec::new();
            if failed >= 1 {
                back.push(Step::Run(launchd::bootout()));
            }
            back.push(Step::Delete(plist.path.clone()));
            back
        }
        Plan::ByHand { .. } => Vec::new(),
    }
}

/// The schedule already on this machine, if any.
///
/// One question, asked by two commands: `--install-timer` refuses when
/// the answer is not empty, and `join` uses it to decide whether to
/// mention installing one at all.
///
/// **Human verification needed**: looks in `/etc/systemd/system` or
/// `/Library/LaunchDaemons`.
pub fn schedule_here(
    machine: Scheduler,
    unit_dir: &Path,
    daemon_dir: &Path,
) -> Result<Vec<PathBuf>, TimerError> {
    let mut here = Vec::new();
    for path in removal(machine, unit_dir, daemon_dir).files() {
        if look(path)? {
            here.push(path.to_path_buf());
        }
    }
    Ok(here)
}

/// How much of a schedule is on this machine.
///
/// What the files can support, and nothing beyond it. A unit on disk
/// does not say whether systemd has it armed, and neither says which
/// `device.json` is baked into its command line — a schedule installed
/// from another user's session reads that user's file and syncs
/// nothing this device joined with (§8).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Present {
    /// None of its files are here.
    None,
    /// Some of them, but not all. Nothing runs from that: a
    /// `anago-sync.timer` with no `anago-sync.service` beside it starts
    /// nothing, and neither does the reverse.
    Partial,
    /// Every file is here.
    Files,
}

/// How much of `expected` files turned up.
pub fn present(expected: usize, found: usize) -> Present {
    match found {
        0 => Present::None,
        found if found >= expected => Present::Files,
        _ => Present::Partial,
    }
}

/// [`present`] against this machine.
///
/// **Human verification needed**: looks in `/etc/systemd/system` or
/// `/Library/LaunchDaemons`.
pub fn present_here(machine: Scheduler, unit_dir: &Path, daemon_dir: &Path) -> Present {
    let expected = removal(machine, unit_dir, daemon_dir).files().len();
    // An answer that cannot be read counts as nothing found. Of the two
    // ways to be wrong, offering an install that a schedule already
    // there would loudly refuse beats claiming one is there when it is
    // not, which nobody ever finds out.
    let found = schedule_here(machine, unit_dir, daemon_dir)
        .unwrap_or_default()
        .len();
    present(expected, found)
}

/// What `join` says, once the tunnel is up, about staying in step.
///
/// **Advice, never an install.** §6.3 makes the periodic sync a
/// convenience rather than a correctness requirement: the hub routes
/// every device, so one that never syncs still reaches all of them.
/// Two things follow.
///
/// Installing a recurring root job as a side effect of joining is a
/// larger step than the one that was asked for — and it would hand
/// `join` a way to fail that has nothing to do with whether the tunnel
/// works, on the command whose whole job is to get the tunnel working.
/// `server init` installs its unit for the opposite reason: a hub that
/// is not running is not a hub, while a device that is not syncing is
/// still on the network.
///
/// It also has to be true on the machine it is printed on. Telling
/// somebody to install a timer they already have, or one this machine
/// has nothing to install with, is advice that wastes the one moment
/// they were paying attention.
///
/// **And no further than the files reach.** Finding a unit is not
/// finding a working schedule: it may be disarmed, or switched off in
/// System Settings, or carrying another user's `--config`. So the
/// wording for a schedule that is here stops at "here" and hands over
/// the commands that answer the rest.
pub fn advice(machine: Scheduler, present: Present) -> String {
    let every = systemd::span(crate::cli::DEFAULT_INTERVAL);
    match present {
        Present::Partial => format!(
            "Some of a sync schedule's files are here, but not all of them — which\n\
             runs nothing at all. `sudo anago sync --uninstall-timer` clears what is\n\
             left, and `--install-timer` then installs a whole one that checks the\n\
             hub every {every}.\n"
        ),
        Present::Files => {
            // Two questions the files cannot answer, and the commands
            // that can. On a mac one command answers both, because
            // `print` shows ProgramArguments alongside the state.
            let asks = match machine {
                Scheduler::Launchd => format!(
                    "     sudo {}\n\n     \
                     macOS can also switch it off under Login Items & Extensions in\n     \
                     System Settings, which looks exactly like one that never runs.\n",
                    launchd::print().display()
                ),
                _ => format!(
                    "     {}\n     {}\n",
                    systemd::is_active_sync_timer().display(),
                    systemd::cat_sync_service().display()
                ),
            };
            format!(
                "A sync schedule is already installed here. That its files are in\n\
                 place does not say whether it is running, or which device file it\n\
                 reads:\n\n\
                 {asks}\n     \
                 If it is not running, or reads a different device file, `sudo anago\n     \
                 sync --uninstall-timer` and then `--install-timer` puts one here\n     \
                 that reads this device's.\n"
            )
        }
        Present::None => match machine {
            Scheduler::Systemd | Scheduler::Launchd => format!(
                "Nothing here watches the hub for changes yet, and nothing has to —\n\
                 the hub routes every device, so this tunnel works either way. A check\n\
                 every {every} is how you hear about a new server key, or about this\n\
                 device being removed:\n\n     \
                 sudo anago sync --install-timer\n\n     \
                 `anago sync` runs one check now and installs nothing.\n"
            ),
            Scheduler::Neither => format!(
                "Nothing here watches the hub for changes yet, and nothing has to —\n\
                 the hub routes every device, so this tunnel works either way. This\n\
                 machine has neither systemd nor launchd, so there is no schedule to\n\
                 install; `sudo anago sync --install-timer` prints the crontab line for\n\
                 a check every {every}, and `anago sync` runs one now.\n"
            ),
        },
    }
}

/// Installs and starts it.
///
/// **Human verification needed**: writes into `/etc/systemd/system` or
/// `/Library/LaunchDaemons` and runs `systemctl`/`launchctl`, so it
/// needs one of those machines and root.
pub fn install(machine: Scheduler, setup: &Setup) -> Result<String, TimerError> {
    let have = Existing {
        joined: look(setup.device_file)?,
        schedule: schedule_here(machine, setup.unit_dir, setup.daemon_dir)?,
    };
    let plan = plan(machine, &have, setup)?;

    let steps = steps(&plan);
    for (index, step) in steps.iter().enumerate() {
        if let Err(e) = perform(step) {
            return Err(unwind(&plan, index, e));
        }
    }
    Ok(report(&plan, setup.device_file))
}

/// Runs [`rewind`] and folds what it could not do into the error.
///
/// Best effort, and honest about it: every step is attempted even if an
/// earlier one failed, because the later ones are the ones that take
/// the files away. What could not be done is named, because a machine
/// left half-changed by a rollback is exactly the state a person needs
/// told about.
fn unwind(plan: &Plan, failed: usize, cause: TimerError) -> TimerError {
    let mut stuck = Vec::new();
    for step in rewind(plan, failed) {
        if perform(&step).is_err() {
            stuck.push(step.describe());
        }
    }
    if stuck.is_empty() {
        return cause;
    }
    TimerError::HalfUndone {
        cause: cause.to_string(),
        left: stuck.join(", "),
    }
}

/// Does one step.
///
/// **Human verification needed**: writes system files and spawns
/// `systemctl`/`launchctl`.
fn perform(step: &Step) -> Result<(), TimerError> {
    match step {
        // Explicit mode, never the umask's: a world-writable systemd
        // unit is one any user can rewrite before the next reload, and
        // launchd refuses a group-writable daemon outright.
        Step::Write(file) => {
            crate::fsutil::write_system(&file.path, &file.text).map_err(|e| TimerError::Io {
                what: format!("write {}", file.path.display()),
                kind: e.kind(),
                source: e.to_string(),
                target: Some(Target::system_file(file.path.clone())),
            })
        }
        Step::Delete(path) => match std::fs::remove_file(path) {
            Ok(()) => Ok(()),
            // A step that never got as far as writing this file is a
            // step with nothing to undo.
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(TimerError::Io {
                what: format!("remove {}", path.display()),
                kind: e.kind(),
                source: e.to_string(),
                target: Some(Target::system_file(path.clone())),
            }),
        },
        Step::Run(cmd) => run(cmd),
    }
}

/// Is it there? An unreadable answer is not a "no".
fn look(path: &Path) -> Result<bool, TimerError> {
    path.try_exists().map_err(|e| TimerError::Io {
        what: format!("look for {}", path.display()),
        kind: e.kind(),
        source: e.to_string(),
        target: None,
    })
}

/// Stops it and takes it away.
///
/// Forgiving about what was never there: the documented repair for a
/// schedule pointing at the wrong file is uninstall-then-install (§8),
/// so a half-installed or already-removed one has to come out without
/// an error. **Not forgiving about what it cannot confirm** — a file
/// that will not go, and a schedule that would not stop, are both
/// failures. Deleting a plist does not stop the daemon it started, so
/// "the files are gone" is not the same sentence as "it is not running".
///
/// The files go either way. Whatever state the machine is in, having
/// them gone is closer to the one that was asked for.
///
/// **Human verification needed**: runs `systemctl`/`launchctl`.
pub fn uninstall(removal: &Removal) -> Result<String, TimerError> {
    // Stop it before the files go: `systemctl disable` reads the unit
    // to find what to unlink, and `launchctl bootout` wants the service
    // it is booting out.
    let stop = match removal {
        Removal::Systemd { .. } => Some(run(&systemd::disable_sync_timer())),
        Removal::Launchd { .. } => Some(run(&launchd::bootout())),
        Removal::Neither => None,
    };

    let mut gone = Vec::new();
    for path in removal.files() {
        match std::fs::remove_file(path) {
            Ok(()) => gone.push(path.to_path_buf()),
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => {
                return Err(TimerError::Io {
                    what: format!("remove {}", path.display()),
                    kind: e.kind(),
                    source: e.to_string(),
                    target: Some(Target::system_file(path.to_path_buf())),
                });
            }
        }
    }
    if let Removal::Systemd { .. } = removal {
        if !gone.is_empty() {
            run(&systemd::daemon_reload())?;
        }
    }

    // Asked after the deletions, because the question is about the
    // state this command is leaving behind.
    let state = match &stop {
        None => Stopped::Gone,
        Some(Ok(())) => Stopped::Gone,
        Some(Err(_)) => stopped(false, still_loaded(removal)),
    };
    if matches!(state, Stopped::StillThere | Stopped::Unknown) {
        let why = match stop {
            Some(Err(e)) => e.to_string(),
            _ => unreachable!("only a failed stop leaves this in doubt"),
        };
        return Err(TimerError::NotStopped {
            why,
            confirmed: state == Stopped::StillThere,
            check: check_command(removal.scheduler()),
        });
    }
    Ok(removal_report(removal, &gone, state))
}

/// Asks whether it is still loaded. `None` when the question could not
/// be put — which is not a "no".
///
/// **Human verification needed**: spawns `systemctl`/`launchctl`.
fn still_loaded(removal: &Removal) -> Option<bool> {
    let ask = match removal {
        Removal::Systemd { .. } => systemd::is_active_sync_timer(),
        Removal::Launchd { .. } => launchd::print(),
        Removal::Neither => return Some(false),
    };
    match std::process::Command::new(&ask.program)
        .args(&ask.args)
        .output()
    {
        Ok(output) => still_there(
            removal.scheduler(),
            output.status.success(),
            &String::from_utf8_lossy(&output.stdout),
            &String::from_utf8_lossy(&output.stderr),
        ),
        // The tool would not even run, so nothing was learned.
        Err(_) => None,
    }
}

/// How a person checks for themselves, in the one message that has to
/// ask them to.
pub fn check_command(machine: Scheduler) -> String {
    match machine {
        Scheduler::Systemd => format!("`{}`", systemd::is_active_sync_timer().display()),
        // `print` shows ProgramArguments too, so on a mac one command
        // answers both "is it there?" and "what does it read?".
        Scheduler::Launchd => format!("`sudo {}`", launchd::print().display()),
        Scheduler::Neither => String::new(),
    }
}

/// **Human verification needed**: spawns `systemctl` or `launchctl`.
fn run(cmd: &Cmd) -> Result<(), TimerError> {
    let output = std::process::Command::new(&cmd.program)
        .args(&cmd.args)
        .output()
        .map_err(|e| TimerError::Spawn {
            line: cmd.display(),
            source: e.to_string(),
        })?;
    if output.status.success() {
        return Ok(());
    }
    Err(TimerError::Failed {
        line: cmd.display(),
        stderr: String::from_utf8_lossy(&output.stderr).trim().to_string(),
    })
}

/// Why the schedule could not be installed or removed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TimerError {
    NotJoined {
        device_file: PathBuf,
    },
    /// There is already a schedule here.
    AlreadyInstalled {
        files: Vec<PathBuf>,
    },
    /// The install failed, and putting the machine back did not fully
    /// work either.
    HalfUndone {
        cause: String,
        left: String,
    },
    /// The files are gone but the schedule was not confirmed stopped.
    NotStopped {
        why: String,
        /// `true` when the check said it is still loaded, `false` when
        /// the check could not say. Different sentences: one is a fact
        /// about the machine, the other is the absence of one.
        confirmed: bool,
        check: String,
    },
    /// The unit text could not be rendered.
    Unit(systemd::Unusable),
    /// The property list could not be rendered.
    Plist(launchd::Unrepresentable),
    /// cron cannot say this period.
    NotCron {
        interval: Duration,
    },
    NotText(PathBuf),
    NotOneLine(PathBuf),
    /// A backslash, in a path bound for a crontab line.
    Backslash(PathBuf),
    Io {
        what: String,
        kind: io::ErrorKind,
        source: String,
        target: Option<Target>,
    },
    Spawn {
        line: String,
        source: String,
    },
    Failed {
        line: String,
        stderr: String,
    },
}

impl From<systemd::Unusable> for TimerError {
    fn from(e: systemd::Unusable) -> TimerError {
        TimerError::Unit(e)
    }
}

impl From<launchd::Unrepresentable> for TimerError {
    fn from(e: launchd::Unrepresentable) -> TimerError {
        TimerError::Plist(e)
    }
}

impl fmt::Display for TimerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TimerError::NotJoined { device_file } => write!(
                f,
                "there is no device file at {} — a timer pointing at nothing would \
                 fail every few minutes while looking installed, so join this device \
                 first with `anago join <domain> <code>`",
                device_file.display()
            ),
            TimerError::AlreadyInstalled { files } => write!(
                f,
                "a sync schedule is already installed ({}) — `anago sync \
                 --uninstall-timer` takes it away, and installing again after that \
                 is how the period changes. It is not replaced in place because a \
                 failure part-way through would leave neither the old schedule nor \
                 the new one",
                files
                    .iter()
                    .map(|path| path.display().to_string())
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
            TimerError::HalfUndone { cause, left } => write!(
                f,
                "{cause} — and undoing it did not fully work: could not {left}. \
                 Run `anago sync --uninstall-timer` to clear whatever is left"
            ),
            TimerError::NotStopped {
                why,
                confirmed,
                check,
            } => {
                let state = if *confirmed {
                    "the schedule is still loaded and will keep running"
                } else {
                    "whether the schedule stopped could not be confirmed, so it may \
                     still be loaded and running"
                };
                write!(
                    f,
                    "{why} — the files are gone, but {state} until this machine \
                     reboots. {check} says whether it is still there"
                )
            }
            TimerError::Unit(e) => write!(f, "{e}"),
            TimerError::Plist(e) => write!(f, "{e}"),
            TimerError::NotCron { interval } => write!(
                f,
                "cron repeats on the clock, not on a stopwatch, so it can only run \
                 something every N minutes when N divides an hour (or every N hours \
                 when N divides a day) — {} is not one of those. This machine has no \
                 systemd and no launchd, so pick a period cron can keep, such as 1m, \
                 5m, 15m, 30m, 1h, 6h or 24h",
                systemd::span(*interval)
            ),
            TimerError::NotText(path) => write!(
                f,
                "{} is not valid UTF-8, so a crontab line could only name a different \
                 path than the one you meant",
                path.to_string_lossy().escape_debug()
            ),
            TimerError::NotOneLine(path) => write!(
                f,
                "{} has a control character in it, and a crontab is read one line at \
                 a time — no quoting survives that",
                path.to_string_lossy().escape_debug()
            ),
            TimerError::Backslash(path) => write!(
                f,
                "{} has a backslash in it, and cron escapes the line before the shell \
                 sees it — a backslash there changes which character the escape eats, \
                 which is how a `%` later in the path ends up cutting the command in \
                 half. systemd and launchd take the path as it is; only a crontab \
                 cannot",
                path.to_string_lossy().escape_debug()
            ),
            TimerError::Io {
                what,
                kind,
                source,
                target,
            } => f.write_str(&crate::diagnostics::with_target_advice(
                format!("could not {what}: {source}"),
                target.as_ref(),
                *kind,
            )),
            TimerError::Spawn { line, source } => {
                write!(f, "could not run `{line}`: {source}")
            }
            TimerError::Failed { line, stderr } => {
                write!(f, "`{line}` failed")?;
                if !stderr.is_empty() {
                    write!(f, ": {stderr}")?;
                }
                Ok(())
            }
        }
    }
}

impl std::error::Error for TimerError {}

#[cfg(all(test, unix))] // installs systemd/launchd/cron schedules — unix execution surfaces; path semantics differ on Windows
mod tests {
    use super::*;

    fn plan_for(machine: Scheduler, setup: &Setup) -> Plan {
        plan(machine, &nothing_yet(true), setup).expect("a plain install")
    }

    /// A machine with a device file and no schedule on it yet.
    fn nothing_yet(joined: bool) -> Existing {
        Existing {
            joined,
            schedule: Vec::new(),
        }
    }

    const EVERY_FIVE: Duration = Duration::from_secs(5 * 60);

    fn setup<'a>(device_file: &'a Path, exec: &'a Path) -> Setup<'a> {
        Setup {
            exec,
            device_file,
            wg_config: Path::new("/etc/wireguard/anago.conf"),
            interval: EVERY_FIVE,
            unit_dir: Path::new("/etc/systemd/system"),
            daemon_dir: Path::new("/Library/LaunchDaemons"),
        }
    }

    fn linux() -> Setup<'static> {
        setup(
            Path::new("/home/jo/.config/anago/device.json"),
            Path::new("/usr/local/bin/anago"),
        )
    }

    fn mac() -> Setup<'static> {
        setup(
            Path::new("/Users/jo/.config/anago/device.json"),
            Path::new("/usr/local/bin/anago"),
        )
    }

    #[test]
    fn the_machine_decides_which_scheduler_and_systemd_goes_first() {
        assert_eq!(scheduler(true, false), Scheduler::Systemd);
        assert_eq!(scheduler(false, true), Scheduler::Launchd);
        assert_eq!(scheduler(false, false), Scheduler::Neither);
        // Not expected to happen, but a Linux box with a
        // `/Library/LaunchDaemons` lying around still runs systemd.
        assert_eq!(scheduler(true, true), Scheduler::Systemd);
    }

    #[test]
    fn a_device_that_has_not_joined_gets_no_schedule() {
        // §8: a timer pointing at nothing is worse than no timer. It
        // fails every five minutes in a log nobody reads while the
        // person believes they are syncing.
        for machine in [Scheduler::Systemd, Scheduler::Launchd, Scheduler::Neither] {
            assert_eq!(
                plan(machine, &nothing_yet(false), &linux()),
                Err(TimerError::NotJoined {
                    device_file: PathBuf::from("/home/jo/.config/anago/device.json")
                }),
                "{machine:?}"
            );
        }
        let e = plan(Scheduler::Systemd, &nothing_yet(false), &linux()).unwrap_err();
        assert!(e.to_string().contains("anago join"), "{e}");
        assert_eq!(e.to_string().lines().count(), 1, "{e}");
    }

    #[test]
    fn systemd_gets_the_pair_of_units() {
        let Plan::Systemd { service, timer } =
            plan(Scheduler::Systemd, &nothing_yet(true), &linux()).unwrap()
        else {
            panic!("systemd installs units");
        };
        assert_eq!(
            service.path,
            Path::new("/etc/systemd/system/anago-sync.service")
        );
        assert_eq!(
            timer.path,
            Path::new("/etc/systemd/system/anago-sync.timer")
        );
        // The device file resolved now, baked into the unit — the whole
        // reason the install happens while sudo still knows who ran it.
        assert!(
            service
                .text
                .contains("--config /home/jo/.config/anago/device.json"),
            "{}",
            service.text
        );
        assert!(
            timer.text.contains("OnUnitActiveSec=5min"),
            "{}",
            timer.text
        );
    }

    #[test]
    fn a_mac_gets_the_daemon() {
        let Plan::Launchd { plist } = plan(Scheduler::Launchd, &nothing_yet(true), &mac()).unwrap()
        else {
            panic!("a mac installs a LaunchDaemon");
        };
        assert_eq!(
            plist.path,
            Path::new("/Library/LaunchDaemons/com.github.elpalaiso.anago.sync.plist")
        );
        assert!(
            plist
                .text
                .contains("<string>/Users/jo/.config/anago/device.json</string>"),
            "{}",
            plist.text
        );
        assert!(
            plist.text.contains("<integer>300</integer>"),
            "{}",
            plist.text
        );
    }

    #[test]
    fn a_machine_with_neither_is_told_rather_than_lied_to() {
        // §8: do not mime an install. The same answer
        // `server init --no-systemd` gives.
        let Plan::ByHand { line } = plan(Scheduler::Neither, &nothing_yet(true), &linux()).unwrap()
        else {
            panic!("neither means guidance");
        };
        assert_eq!(
            line,
            "*/5 * * * * /usr/local/bin/anago sync --quiet \
             --config /home/jo/.config/anago/device.json"
        );
        // Nothing was written, and the report says so before it says
        // anything else.
        let text = report(&Plan::ByHand { line }, linux().device_file);
        assert!(text.contains("nothing was"), "{text}");
        assert!(text.contains("sudo crontab -e"), "{text}");
    }

    #[test]
    fn cron_only_promises_periods_it_can_keep() {
        let every = |seconds| cron_schedule(Duration::from_secs(seconds));
        assert_eq!(every(60).unwrap(), "* * * * *");
        assert_eq!(every(5 * 60).unwrap(), "*/5 * * * *");
        assert_eq!(every(15 * 60).unwrap(), "*/15 * * * *");
        assert_eq!(every(30 * 60).unwrap(), "*/30 * * * *");
        assert_eq!(every(60 * 60).unwrap(), "0 * * * *");
        assert_eq!(every(6 * 60 * 60).unwrap(), "0 */6 * * *");
        assert_eq!(every(24 * 60 * 60).unwrap(), "0 0 * * *");
        // cron runs on the clock, not on a stopwatch. `*/7` is minutes
        // 0, 7 … 56 and then a four-minute gap at the hour, so it is
        // not "every seven minutes" and must not be offered as one.
        assert_eq!(every(7 * 60), None);
        assert_eq!(every(90), None, "not whole minutes");
        assert_eq!(every(5 * 60 * 60), None, "5 does not divide 24");
        assert_eq!(every(0), None);
        // Refused rather than rounded: the person asked for a period,
        // and a different one silently kept is not an answer.
        let e = plan(
            Scheduler::Neither,
            &nothing_yet(true),
            &Setup {
                interval: Duration::from_secs(90),
                ..linux()
            },
        )
        .unwrap_err();
        assert_eq!(
            e,
            TimerError::NotCron {
                interval: Duration::from_secs(90)
            }
        );
        assert!(e.to_string().contains("90s"), "{e}");
        assert_eq!(e.to_string().lines().count(), 1, "{e}");
        // The same period is fine where something can actually keep it.
        assert!(plan(
            Scheduler::Systemd,
            &nothing_yet(true),
            &Setup {
                interval: Duration::from_secs(90),
                ..linux()
            }
        )
        .is_ok());
    }

    #[test]
    fn a_crontab_line_survives_the_two_things_that_read_it() {
        // The shell gets it second, so a space has to be quoted or the
        // path becomes two arguments.
        let line = crontab_command(
            Path::new("/opt/my anago/anago"),
            Path::new("/home/jo/my files/device.json"),
        )
        .unwrap();
        assert_eq!(
            line,
            "'/opt/my anago/anago' sync --quiet --config '/home/jo/my files/device.json'"
        );
        // cron gets it first, and an unescaped % ends the command —
        // everything after it becomes standard input, so the line would
        // silently shorten into one that still runs.
        let line = crontab_command(
            Path::new("/usr/local/bin/anago"),
            Path::new("/home/jo/100%/device.json"),
        )
        .unwrap();
        // The backslash lands inside the quotes, and that is right:
        // cron unescapes `\%` before the shell ever sees the line, so
        // what reaches sh is the quoted path with a plain % in it.
        assert_eq!(
            line,
            "/usr/local/bin/anago sync --quiet --config '/home/jo/100\\%/device.json'"
        );
        // A single quote closes the quoted run; '\'' closes, escapes
        // one, and opens again.
        assert_eq!(
            crontab_command(
                Path::new("/usr/local/bin/anago"),
                Path::new("/home/jo/o'brien/device.json"),
            )
            .unwrap(),
            "/usr/local/bin/anago sync --quiet --config '/home/jo/o'\\''brien/device.json'"
        );
        // Ordinary paths are left alone — a crontab is something a
        // person reads and edits.
        assert!(!crontab_command(
            Path::new("/usr/local/bin/anago"),
            Path::new("/home/jo/.config/anago/device.json"),
        )
        .unwrap()
        .contains('\''));
    }

    #[test]
    fn a_backslash_in_a_path_gets_no_crontab_line() {
        // cron escapes the line before the shell sees it, and its pass
        // consumes the character after a backslash. So a literal one
        // shifts what gets consumed: `…/a\%b` escaped to `…/a\\%b` has
        // the first backslash eat the second, leaving the `%` bare and
        // the command cut in half at exactly the wrong place. Getting
        // that right means depending on a parser this code cannot run,
        // on a line that runs as root.
        for text in [
            "/home/jo/a\\%b/device.json",
            "/home/jo/a\\b/device.json",
            "/home/jo/back\\slash/device.json",
        ] {
            assert_eq!(
                crontab_command(Path::new("/usr/local/bin/anago"), Path::new(text)),
                Err(TimerError::Backslash(PathBuf::from(text))),
                "{text}"
            );
        }
        assert_eq!(
            crontab_command(
                Path::new("/opt/a\\b/anago"),
                Path::new("/home/jo/device.json")
            ),
            Err(TimerError::Backslash(PathBuf::from("/opt/a\\b/anago")))
        );
        // Whatever a crontab line does hold, every `\%` in it is one
        // this code put there — nothing else can have shifted it.
        let line = crontab_command(
            Path::new("/usr/local/bin/anago"),
            Path::new("/home/jo/100%/device.json"),
        )
        .unwrap();
        assert_eq!(line.matches('\\').count(), line.matches("\\%").count());
        assert_eq!(line.matches('%').count(), line.matches("\\%").count());

        // Only the crontab minds. The same path installs fine where
        // something can actually schedule it, so the refusal is not
        // repeated at lines where it would not be true.
        let awkward = setup(
            Path::new("/home/jo/a\\%b/device.json"),
            Path::new("/usr/local/bin/anago"),
        );
        assert!(plan(Scheduler::Systemd, &nothing_yet(true), &awkward).is_ok());
        assert!(plan(Scheduler::Launchd, &nothing_yet(true), &awkward).is_ok());
        let e = plan(Scheduler::Neither, &nothing_yet(true), &awkward).unwrap_err();
        assert!(e.to_string().contains("only a crontab cannot"), "{e}");
        assert_eq!(e.to_string().lines().count(), 1, "{e}");
    }

    #[test]
    fn a_path_a_crontab_cannot_hold_is_refused() {
        // A crontab is read one line at a time, like a unit file, and
        // no quoting survives a newline either.
        let broken = Path::new("/home/jo/a\nb/device.json");
        assert_eq!(
            crontab_command(Path::new("/usr/local/bin/anago"), broken),
            Err(TimerError::NotOneLine(broken.to_path_buf()))
        );
        assert_eq!(
            crontab_command(Path::new("/opt/a\tb/anago"), broken),
            Err(TimerError::NotOneLine(PathBuf::from("/opt/a\tb/anago")))
        );
        for e in [
            TimerError::NotOneLine(PathBuf::from("/home/jo/a\nb")),
            TimerError::NotText(PathBuf::from("/home/jo/ab")),
        ] {
            assert_eq!(e.to_string().lines().count(), 1, "{e}");
        }
    }

    #[test]
    fn the_render_refusals_come_through_rather_than_being_swallowed() {
        // A `--config` no unit file can name has to stop the install,
        // not produce a broken one.
        assert_eq!(
            plan(
                Scheduler::Systemd,
                &nothing_yet(true),
                &setup(
                    Path::new("/home/jo/a:b/device.json"),
                    Path::new("/usr/local/bin/anago")
                )
            ),
            Err(TimerError::Unit(systemd::Unusable::NotBindable(
                PathBuf::from("/home/jo/a:b")
            )))
        );
        assert_eq!(
            plan(
                Scheduler::Launchd,
                &nothing_yet(true),
                &setup(
                    Path::new("/Users/jo/a\u{0}b/device.json"),
                    Path::new("/usr/local/bin/anago")
                )
            ),
            Err(TimerError::Plist(launchd::Unrepresentable::NotXml(
                PathBuf::from("/Users/jo/a\u{0}b/device.json")
            )))
        );
        // The same colon is fine on a mac, which has no bind list.
        assert!(plan(
            Scheduler::Launchd,
            &nothing_yet(true),
            &setup(
                Path::new("/Users/jo/a:b/device.json"),
                Path::new("/usr/local/bin/anago")
            )
        )
        .is_ok());
    }

    #[test]
    fn every_install_says_which_file_it_reads_and_how_to_check() {
        // §8 keeps no "is the timer installed?" surface, so the install
        // output is all there is — and it has to name the device file,
        // because the mistake it exists to catch is a schedule reading
        // root's `device.json` instead of the one somebody joined with.
        for (machine, needles) in [
            (
                Scheduler::Systemd,
                vec![
                    "systemctl list-timers 'anago-sync*'",
                    "systemctl cat anago-sync.service",
                ],
            ),
            (
                Scheduler::Launchd,
                vec![
                    "sudo launchctl print system/com.github.elpalaiso.anago.sync",
                    "System Settings",
                ],
            ),
            (Scheduler::Neither, vec!["sudo crontab -e"]),
        ] {
            let device = match machine {
                Scheduler::Launchd => mac(),
                _ => linux(),
            };
            let text = report(
                &plan(machine, &nothing_yet(true), &device).unwrap(),
                device.device_file,
            );
            for needle in needles {
                assert!(
                    text.contains(needle),
                    "{machine:?} missing {needle}: {text}"
                );
            }
            assert!(
                text.contains(&device.device_file.display().to_string()),
                "{machine:?}: {text}"
            );
        }
    }

    #[test]
    fn joining_offers_the_timer_and_never_installs_it() {
        // §6.3 makes the periodic sync a convenience, not a
        // correctness requirement — so `join` must not leave a
        // recurring root job behind as a side effect, and must not
        // acquire a way to fail that has nothing to do with the tunnel
        // it was asked to bring up.
        for machine in [Scheduler::Systemd, Scheduler::Launchd, Scheduler::Neither] {
            let text = advice(machine, Present::None);
            assert!(
                text.contains("sudo anago sync --install-timer"),
                "{machine:?}: {text}"
            );
            // Says what it did not do, in both directions.
            assert!(text.contains("nothing has to"), "{machine:?}: {text}");
            assert!(
                text.contains("works either way"),
                "the tunnel does not depend on it: {machine:?}: {text}"
            );
            for claim in ["is installed", "is running", "was installed"] {
                assert!(!text.contains(claim), "{machine:?} claims {claim}: {text}");
            }
            // The period it offers is the one the command defaults to.
            assert!(text.contains("5min"), "{machine:?}: {text}");
        }
        // The bare offer belongs to an empty machine only: with files
        // already there, `--install-timer` on its own refuses.
        for machine in [Scheduler::Systemd, Scheduler::Launchd] {
            for present in [Present::Files, Present::Partial] {
                let text = advice(machine, present);
                assert!(
                    !text.contains("sudo anago sync --install-timer"),
                    "{machine:?} {present:?}: {text}"
                );
            }
        }

        // And one check now is always the smaller alternative.
        assert!(
            advice(Scheduler::Systemd, Present::None).contains("`anago sync` runs one check now")
        );
        assert!(advice(Scheduler::Neither, Present::None).contains("`anago sync` runs one now"));
    }

    #[test]
    fn a_machine_that_cannot_schedule_is_told_so_here_too() {
        // Sending somebody to `--install-timer` and letting them find
        // out there is the wasted version of the one moment they were
        // paying attention.
        let text = advice(Scheduler::Neither, Present::None);
        assert!(text.contains("neither systemd nor launchd"), "{text}");
        assert!(text.contains("crontab line"), "{text}");
        assert!(
            !text.contains("no schedule to install\n     sudo"),
            "{text}"
        );
        // The two that can schedule do not mention crontabs.
        for machine in [Scheduler::Systemd, Scheduler::Launchd] {
            assert!(
                !advice(machine, Present::None).contains("crontab"),
                "{machine:?}"
            );
        }
    }

    #[test]
    fn finding_the_files_is_not_finding_a_working_schedule() {
        // A unit on disk does not say systemd has it armed, and neither
        // says which `device.json` is baked into its command line — one
        // installed from another user's session reads that user's file
        // and syncs nothing this device joined with. So the wording
        // stops at what the files support.
        for (machine, asks) in [
            (
                Scheduler::Systemd,
                vec![
                    "systemctl is-active anago-sync.timer",
                    "systemctl cat anago-sync.service",
                ],
            ),
            (
                Scheduler::Launchd,
                vec!["sudo launchctl print system/com.github.elpalaiso.anago.sync"],
            ),
        ] {
            let text = advice(machine, Present::Files);
            // The limit is said outright rather than left to be
            // inferred from what the sentence did not claim.
            assert!(
                text.contains(
                    "That its files are in\nplace does not say whether it is running, \
                     or which device file it\nreads"
                ),
                "{machine:?}: {text}"
            );
            // The claims the old wording made from the same evidence.
            for claim in ["is watched", "being watched", "will sync", "is syncing"] {
                assert!(!text.contains(claim), "{machine:?} claims {claim}: {text}");
            }
            for ask in asks {
                assert!(text.contains(ask), "{machine:?} missing {ask}: {text}");
            }
            // The repair, when the answer to either question is the
            // wrong one. `--install-timer` on its own would refuse.
            let install = text.find("--install-timer").expect("names the repair");
            let uninstall = text.find("--uninstall-timer").expect("names the repair");
            assert!(uninstall < install, "{machine:?}: {text}");
        }
        // macOS has a third way to look installed and never run.
        assert!(advice(Scheduler::Launchd, Present::Files).contains("Login Items"));
    }

    #[test]
    fn half_a_schedule_is_told_apart_from_a_whole_one() {
        // A timer with no service beside it starts nothing, and the
        // reverse starts nothing either — but both leave a file, so
        // "something is here" would read as "you are covered".
        assert_eq!(present(2, 0), Present::None);
        assert_eq!(present(2, 1), Present::Partial);
        assert_eq!(present(2, 2), Present::Files);
        // launchd installs one file, so it has no half.
        assert_eq!(present(1, 0), Present::None);
        assert_eq!(present(1, 1), Present::Files);
        // A machine with nothing to install has nothing to find.
        assert_eq!(present(0, 0), Present::None);

        let text = advice(Scheduler::Systemd, Present::Partial);
        assert!(text.contains("runs nothing at all"), "{text}");
        let uninstall = text.find("--uninstall-timer").expect("clears it first");
        let install = text.find("--install-timer").expect("then installs one");
        assert!(uninstall < install, "{text}");
        // Not the sentence for a whole one, and not the offer either.
        assert!(!text.contains("already installed here"), "{text}");
        assert!(!text.contains("nothing has to"), "{text}");
    }

    #[test]
    fn the_advice_and_the_install_name_the_same_commands() {
        // Two places tell people how to look at the schedule. They come
        // from the same builders so they cannot drift into naming units
        // that no longer exist.
        assert_eq!(
            systemd::cat_sync_service().display(),
            "systemctl cat anago-sync.service"
        );
        let installed = report(&plan_for(Scheduler::Systemd, &linux()), linux().device_file);
        for text in [installed, advice(Scheduler::Systemd, Present::Files)] {
            assert!(
                text.contains(&systemd::cat_sync_service().display()),
                "{text}"
            );
        }
        let mac_report = report(&plan_for(Scheduler::Launchd, &mac()), mac().device_file);
        for text in [mac_report, advice(Scheduler::Launchd, Present::Files)] {
            assert!(text.contains(&launchd::print().display()), "{text}");
        }
    }

    #[test]
    fn a_schedule_is_never_replaced_in_place() {
        // Overwriting one means a failure at the step after the write
        // leaves neither the old schedule nor the new one, and putting
        // the old bytes back is not enough by then: systemd has already
        // reloaded them, or launchd has taken the new file.
        let already = Existing {
            joined: true,
            schedule: vec![PathBuf::from("/etc/systemd/system/anago-sync.timer")],
        };
        assert_eq!(
            plan(Scheduler::Systemd, &already, &linux()),
            Err(TimerError::AlreadyInstalled {
                files: vec![PathBuf::from("/etc/systemd/system/anago-sync.timer")],
            })
        );
        let e = plan(Scheduler::Systemd, &already, &linux()).unwrap_err();
        assert!(e.to_string().contains("--uninstall-timer"), "{e}");
        assert!(e.to_string().contains("anago-sync.timer"), "{e}");
        assert_eq!(e.to_string().lines().count(), 1, "{e}");
        // Not joined wins over already installed: it is the older
        // problem, and the one whose answer is not "uninstall".
        assert!(matches!(
            plan(
                Scheduler::Systemd,
                &Existing {
                    joined: false,
                    schedule: already.schedule.clone()
                },
                &linux()
            ),
            Err(TimerError::NotJoined { .. })
        ));
    }

    #[test]
    fn what_install_must_not_find_is_what_uninstall_takes_away() {
        // One list, so the two halves cannot drift into disagreeing
        // about which files a schedule occupies.
        let unit_dir = Path::new("/etc/systemd/system");
        let daemon_dir = Path::new("/Library/LaunchDaemons");
        assert_eq!(
            removal(Scheduler::Systemd, unit_dir, daemon_dir).files(),
            [
                Path::new("/etc/systemd/system/anago-sync.service"),
                Path::new("/etc/systemd/system/anago-sync.timer"),
            ]
        );
        assert_eq!(
            removal(Scheduler::Launchd, unit_dir, daemon_dir).files(),
            [Path::new(
                "/Library/LaunchDaemons/com.github.elpalaiso.anago.sync.plist"
            )]
        );
        assert!(removal(Scheduler::Neither, unit_dir, daemon_dir)
            .files()
            .is_empty());
    }

    #[test]
    fn the_install_writes_before_it_reloads_and_reloads_before_it_enables() {
        // `systemctl enable` resolves the unit through the manager,
        // which has not read it until the reload.
        let units = plan_for(Scheduler::Systemd, &linux());
        assert_eq!(
            steps(&units).iter().map(Step::describe).collect::<Vec<_>>(),
            [
                "write /etc/systemd/system/anago-sync.service",
                "write /etc/systemd/system/anago-sync.timer",
                "run `systemctl daemon-reload`",
                "run `systemctl enable --now anago-sync.timer`",
            ]
        );
        let daemon = plan_for(Scheduler::Launchd, &mac());
        assert_eq!(
            steps(&daemon)
                .iter()
                .map(Step::describe)
                .collect::<Vec<_>>(),
            [
                "write /Library/LaunchDaemons/com.github.elpalaiso.anago.sync.plist",
                "run `launchctl bootstrap system \
                 /Library/LaunchDaemons/com.github.elpalaiso.anago.sync.plist`",
            ]
        );
        // Nothing was installed, so nothing is done.
        assert!(steps(&plan_for(Scheduler::Neither, &linux())).is_empty());
    }

    #[test]
    fn a_failure_at_any_step_puts_the_machine_back() {
        // The step at index `failed` did not work; the ones before it
        // did. `plan` refused to install over an existing schedule, so
        // "undo what this run did" and "leave it as it was" are the
        // same list — no copy of somebody else's file is needed.
        let units = plan_for(Scheduler::Systemd, &linux());
        let undo = |failed| {
            rewind(&units, failed)
                .iter()
                .map(Step::describe)
                .collect::<Vec<_>>()
        };
        // The service file's own write failed: it may still have left a
        // file, and the manager was never told to look.
        assert_eq!(
            undo(0),
            [
                "remove /etc/systemd/system/anago-sync.timer",
                "remove /etc/systemd/system/anago-sync.service",
            ]
        );
        assert_eq!(undo(1), undo(0), "still nothing has been reloaded");
        // The reload was attempted, so it has to be told again once the
        // files are gone.
        assert_eq!(
            undo(2),
            [
                "remove /etc/systemd/system/anago-sync.timer",
                "remove /etc/systemd/system/anago-sync.service",
                "run `systemctl daemon-reload`",
            ]
        );
        // A failed `enable --now` is not a no-op: it can leave some of
        // the symlinks it was making, and deleting the unit underneath
        // them leaves those dangling.
        assert_eq!(
            undo(3),
            [
                "run `systemctl disable --now anago-sync.timer`",
                "remove /etc/systemd/system/anago-sync.timer",
                "remove /etc/systemd/system/anago-sync.service",
                "run `systemctl daemon-reload`",
            ]
        );

        let daemon = plan_for(Scheduler::Launchd, &mac());
        let undo = |failed| {
            rewind(&daemon, failed)
                .iter()
                .map(Step::describe)
                .collect::<Vec<_>>()
        };
        assert_eq!(
            undo(0),
            ["remove /Library/LaunchDaemons/com.github.elpalaiso.anago.sync.plist"]
        );
        // Otherwise a plist reported as a failed install is still there
        // to be loaded at the next boot.
        assert_eq!(
            undo(1),
            [
                "run `launchctl bootout system/com.github.elpalaiso.anago.sync`",
                "remove /Library/LaunchDaemons/com.github.elpalaiso.anago.sync.plist",
            ]
        );

        // Nothing was done, so nothing is undone.
        assert!(rewind(&plan_for(Scheduler::Neither, &linux()), 0).is_empty());
    }

    #[test]
    fn every_file_the_install_writes_is_deleted_by_its_rewind() {
        // The property behind the case-by-case list above: whatever a
        // prefix of `steps` could have created, `rewind` removes.
        for (machine, set) in [(Scheduler::Systemd, linux()), (Scheduler::Launchd, mac())] {
            let made = plan_for(machine, &set);
            let written: Vec<PathBuf> = steps(&made)
                .iter()
                .filter_map(|step| match step {
                    Step::Write(file) => Some(file.path.clone()),
                    _ => None,
                })
                .collect();
            assert!(!written.is_empty(), "{machine:?}");
            for failed in 0..steps(&made).len() {
                let deleted: Vec<PathBuf> = rewind(&made, failed)
                    .iter()
                    .filter_map(|step| match step {
                        Step::Delete(path) => Some(path.clone()),
                        _ => None,
                    })
                    .collect();
                for path in &written {
                    assert!(deleted.contains(path), "{machine:?} at {failed}: {path:?}");
                }
            }
        }
    }

    #[test]
    fn a_rollback_that_did_not_work_says_what_is_left() {
        // A machine left half-changed by a rollback is exactly the
        // state somebody needs telling about.
        let e = TimerError::HalfUndone {
            cause: "`systemctl enable --now anago-sync.timer` failed".to_string(),
            left: "remove /etc/systemd/system/anago-sync.timer".to_string(),
        };
        assert_eq!(e.to_string().lines().count(), 1, "{e}");
        assert!(e.to_string().contains("--uninstall-timer"), "{e}");
        assert!(e.to_string().contains("anago-sync.timer"), "{e}");
    }

    #[test]
    fn removal_needs_no_device_file_and_knows_the_fixed_names() {
        let unit_dir = Path::new("/etc/systemd/system");
        let daemon_dir = Path::new("/Library/LaunchDaemons");
        assert_eq!(
            removal(Scheduler::Systemd, unit_dir, daemon_dir),
            Removal::Systemd {
                service: PathBuf::from("/etc/systemd/system/anago-sync.service"),
                timer: PathBuf::from("/etc/systemd/system/anago-sync.timer"),
            }
        );
        assert_eq!(
            removal(Scheduler::Launchd, unit_dir, daemon_dir),
            Removal::Launchd {
                plist: PathBuf::from(
                    "/Library/LaunchDaemons/com.github.elpalaiso.anago.sync.plist"
                ),
            }
        );
        assert_eq!(
            removal(Scheduler::Neither, unit_dir, daemon_dir),
            Removal::Neither
        );
    }

    #[test]
    fn a_stop_that_did_not_work_is_only_forgiven_when_it_was_not_loaded() {
        // A failed `systemctl disable --now` or `launchctl bootout` is
        // no evidence on its own — the usual cause is that nothing was
        // loaded, and the unusual one is that something is and would
        // not stop. Deleting the files does not separate them: a
        // LaunchDaemon keeps running after its plist is gone, which is
        // the whole reason bootout exists.
        assert_eq!(stopped(true, None), Stopped::Gone);
        assert_eq!(stopped(true, Some(true)), Stopped::Gone);
        assert_eq!(stopped(false, Some(false)), Stopped::NotLoaded);
        // Still there after a failed stop: the one case that must not
        // be reported as a removal.
        assert_eq!(stopped(false, Some(true)), Stopped::StillThere);
        // The question could not be put at all, which is not a "no" —
        // and is not the same sentence as the line above either.
        assert_eq!(stopped(false, None), Stopped::Unknown);
    }

    #[test]
    fn only_a_clear_absence_counts_as_absent() {
        // A non-zero exit from `is-active` or `print` is not "it is
        // gone": both also fail when the manager cannot be reached,
        // when the caller may not ask, or when the IPC underneath
        // breaks. Reading any of those as an absence would report a
        // schedule as removed while it is still running.
        let systemd =
            |ok, stdout: &str, stderr: &str| still_there(Scheduler::Systemd, ok, stdout, stderr);
        assert_eq!(systemd(true, "active\n", ""), Some(true));
        assert_eq!(systemd(false, "inactive\n", ""), Some(false));
        assert_eq!(systemd(false, "failed\n", ""), Some(false));
        assert_eq!(systemd(false, "unknown\n", ""), Some(false));
        // No state word at all: `systemctl` never got as far as asking.
        assert_eq!(
            systemd(
                false,
                "",
                "Failed to connect to bus: No such file or directory"
            ),
            None
        );
        assert_eq!(systemd(false, "", "Access denied"), None);
        // A word it does not know is a word it does not act on.
        assert_eq!(systemd(false, "reloading\n", ""), None);
        assert_eq!(systemd(false, "activating\n", ""), None);

        let launchd = |ok, stderr: &str| still_there(Scheduler::Launchd, ok, "", stderr);
        assert_eq!(launchd(true, ""), Some(true));
        assert_eq!(
            launchd(
                false,
                "Could not find service \"com.github.elpalaiso.anago.sync\" in domain \
                 for system"
            ),
            Some(false)
        );
        assert_eq!(launchd(false, "No such process"), Some(false));
        // Everything else, including the ones that mean the opposite.
        assert_eq!(launchd(false, "Operation not permitted"), None);
        assert_eq!(
            launchd(false, "Bootstrap failed: 5: Input/output error"),
            None
        );
        assert_eq!(launchd(false, ""), None);

        // The two failure states end up in the same place, but they do
        // not say the same thing.
        assert_eq!(
            stopped(false, launchd(false, "Operation not permitted")),
            Stopped::Unknown
        );
        assert_eq!(stopped(false, launchd(true, "")), Stopped::StillThere);
    }

    #[test]
    fn a_schedule_that_would_not_stop_is_a_failure_and_says_so() {
        for (removal, check) in [
            (
                Removal::Systemd {
                    service: PathBuf::from("/etc/systemd/system/anago-sync.service"),
                    timer: PathBuf::from("/etc/systemd/system/anago-sync.timer"),
                },
                "`systemctl is-active anago-sync.timer`",
            ),
            (
                Removal::Launchd {
                    plist: PathBuf::from(
                        "/Library/LaunchDaemons/com.github.elpalaiso.anago.sync.plist",
                    ),
                },
                "`sudo launchctl print system/com.github.elpalaiso.anago.sync`",
            ),
        ] {
            assert_eq!(check_command(removal.scheduler()), check);
            let known = TimerError::NotStopped {
                why: "`launchctl bootout system/…` failed: Operation not permitted".to_string(),
                confirmed: true,
                check: check_command(removal.scheduler()),
            };
            // "the files are gone" is not the same sentence as "it is
            // not running", so the message says both.
            assert!(known.to_string().contains("still loaded"), "{known}");
            assert!(known.to_string().contains(check), "{known}");
            assert_eq!(known.to_string().lines().count(), 1, "{known}");

            // And when the check could not say, the message must not
            // pretend it did — that is a fact about the machine that
            // nobody established.
            let unknown = TimerError::NotStopped {
                why: "`launchctl bootout system/…` failed: Operation not permitted".to_string(),
                confirmed: false,
                check: check_command(removal.scheduler()),
            };
            assert!(
                unknown.to_string().contains("could not be confirmed"),
                "{unknown}"
            );
            assert!(
                !unknown.to_string().contains("is still loaded"),
                "no claim it did not earn: {unknown}"
            );
            assert!(unknown.to_string().contains(check), "{unknown}");
            assert_eq!(unknown.to_string().lines().count(), 1, "{unknown}");
        }
    }

    #[test]
    fn a_removal_says_which_of_the_three_things_happened() {
        let units = Removal::Systemd {
            service: PathBuf::from("/etc/systemd/system/anago-sync.service"),
            timer: PathBuf::from("/etc/systemd/system/anago-sync.timer"),
        };
        let both = [
            PathBuf::from("/etc/systemd/system/anago-sync.service"),
            PathBuf::from("/etc/systemd/system/anago-sync.timer"),
        ];
        // Files were there but nothing was running them — worth saying,
        // because "stopped it" would be a claim about work not done.
        let idle = removal_report(&units, &both, Stopped::NotLoaded);
        assert!(idle.contains("nothing to stop"), "{idle}");
        assert!(!removal_report(&units, &both, Stopped::Gone).contains("nothing to stop"));
        // The reverse: no file left, but it was still loaded. Somebody
        // deleted the unit by hand and it kept running until now.
        let orphan = removal_report(&units, &[], Stopped::Gone);
        assert!(orphan.contains("no file left"), "{orphan}");
        assert!(orphan.contains("still\nloaded"), "{orphan}");
        assert!(
            !removal_report(&units, &[], Stopped::NotLoaded).contains("no file left"),
            "nothing there at all is a different sentence"
        );
    }

    #[test]
    fn removing_nothing_does_not_claim_to_have_removed_something() {
        let units = Removal::Systemd {
            service: PathBuf::from("/etc/systemd/system/anago-sync.service"),
            timer: PathBuf::from("/etc/systemd/system/anago-sync.timer"),
        };
        let nothing = removal_report(&units, &[], Stopped::NotLoaded);
        assert!(nothing.contains("No sync timer was installed"), "{nothing}");

        let both = removal_report(
            &units,
            &[
                PathBuf::from("/etc/systemd/system/anago-sync.service"),
                PathBuf::from("/etc/systemd/system/anago-sync.timer"),
            ],
            Stopped::Gone,
        );
        assert!(both.contains("anago-sync.service"), "{both}");
        assert!(both.contains("anago-sync.timer"), "{both}");

        // anago never wrote the crontab line, so it must not say it
        // took one away — it cannot even see one.
        let by_hand = removal_report(&Removal::Neither, &[], Stopped::NotLoaded);
        assert!(by_hand.contains("anago never wrote one"), "{by_hand}");
        assert!(by_hand.contains("sudo crontab -e"), "{by_hand}");
        assert!(!by_hand.contains("is gone"), "{by_hand}");
    }

    #[test]
    fn the_commands_that_load_and_unload_are_the_right_ones() {
        // The timer is what gets enabled, never the service: enabling
        // the service would run one sync at boot and never another.
        assert_eq!(
            systemd::enable_sync_timer().display(),
            "systemctl enable --now anago-sync.timer"
        );
        assert_eq!(
            systemd::disable_sync_timer().display(),
            "systemctl disable --now anago-sync.timer"
        );
        assert_eq!(
            systemd::daemon_reload().display(),
            "systemctl daemon-reload"
        );
        for cmd in [systemd::enable_sync_timer(), systemd::disable_sync_timer()] {
            assert!(
                !cmd.args.contains(&systemd::SYNC_SERVICE.to_string()),
                "{}",
                cmd.display()
            );
        }
    }
}
