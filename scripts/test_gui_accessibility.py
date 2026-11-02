#!/usr/bin/env python3
"""Native Linux smoke check using isolated profiles, DBus, AT-SPI, and Orca.

Requires PyGObject/GTK3/AT-SPI, Orca, and dbus tools. Optional --orca-runtime
supports an extracted user-local Orca/Speech Dispatcher installation. No personal
vaults or other applications' accessibility trees are inspected. A passing smoke
check is not a complete screen-reader, IME, or platform accessibility review.
"""
import argparse
import json
import os
import re
from pathlib import Path
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, default=Path("target/debug/pm"))
    parser.add_argument("--output", type=Path)
    parser.add_argument("--orca-runtime", type=Path)
    parser.add_argument("--xvfb", type=Path, help="Run native X11 checks on an isolated Xvfb display")
    parser.add_argument("--scale", type=int, choices=[100, 115, 130], default=100,
                        help="Interface scale in the private test profile")
    args = parser.parse_args()
    root = (args.output or Path(tempfile.mkdtemp(prefix="pm-native-a11y-"))).resolve()
    root.mkdir(parents=True, exist_ok=True)
    env = dict(os.environ, GSETTINGS_BACKEND="memory", XDG_CONFIG_HOME=str(root / "config"),
               XDG_DATA_HOME=str(root / "data"), PM_CONFIG_DIR=str(root / "pm-config"),
               PM_DATA_DIR=str(root / "pm-data"))
    if not os.environ.get("PM_NATIVE_A11Y_PRIVATE"):
        env["PM_NATIVE_A11Y_PRIVATE"] = "1"
        command = ["dbus-run-session", "--", sys.executable, str(Path(__file__).resolve()),
                   "--binary", str(args.binary.resolve()), "--output", str(root)]
        command += ["--scale", str(args.scale)]
        if args.orca_runtime:
            command += ["--orca-runtime", str(args.orca_runtime.resolve())]
        if args.xvfb:
            command += ["--xvfb", str(args.xvfb.resolve())]
        return subprocess.run(command, env=env).returncode

    import gi
    gi.require_version("Atspi", "2.0")
    from gi.repository import Atspi, GLib

    runtime = args.orca_runtime.resolve() if args.orca_runtime else None
    orca = shutil.which("orca")
    if runtime:
        orca = str(runtime / "usr/bin/orca")
        env.update(PYTHONPATH=str(runtime / f"usr/lib/python{sys.version_info.major}.{sys.version_info.minor}/site-packages"),
                   LD_LIBRARY_PATH=f"{runtime}/usr/lib:{runtime}/usr/lib/speech-dispatcher",
                   GSETTINGS_SCHEMA_DIR=str(runtime / "usr/share/glib-2.0/schemas"),
                   XDG_DATA_DIRS=f"{runtime}/usr/share:/usr/local/share:/usr/share",
                   ESPEAK_DATA_PATH=str(runtime / "usr/share/espeak-ng-data"))
    if not orca or not Path(orca).exists():
        raise RuntimeError("Install Orca or provide --orca-runtime")

    binary = str(args.binary.resolve())
    processes, files = [], []
    started = False
    bus_pid = None
    result = {"checks": {}, "limitations": ["Smoke check only; full Orca and IME acceptance remains manual."]}

    def launch(command, name, extra=None):
        log = open(root / f"{name}.log", "w")
        files.append(log)
        process = subprocess.Popen(command, env=extra or env, stdout=log, stderr=subprocess.STDOUT)
        processes.append(process)
        return process

    def pm(*command):
        return subprocess.run([binary, *command], env=env, check=True, capture_output=True, timeout=20)

    def wait_for(predicate, timeout=25):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            while GLib.MainContext.default().pending():
                GLib.MainContext.default().iteration(False)
            try:
                value = predicate()
            except GLib.Error as error:
                if "Unknown object" not in str(error) and "/org/a11y/atspi/accessible/" not in str(error):
                    raise
                value = None
            if value:
                return value
            time.sleep(0.1)
        raise AssertionError("Native accessibility check timed out")

    def nodes(application):
        rows = []
        def walk(node, depth=0):
            if depth > 20:
                return
            node.clear_cache()
            rows.append(node)
            for index in range(min(node.get_child_count(), 200)):
                child = node.get_child_at_index(index)
                if child:
                    walk(child, depth + 1)
        walk(application)
        return rows

    def application(pid):
        desktop = Atspi.get_desktop(0)
        if desktop:
            for index in range(desktop.get_child_count()):
                candidate = desktop.get_child_at_index(index)
                if candidate.get_process_id() == pid:
                    candidate.clear_cache()
                    return candidate

    def find(pid, role, name):
        app = application(pid)
        roles = [role] if isinstance(role, str) else role
        return next((node for node in nodes(app) if node.get_role_name() in roles and node.get_name() == name), None) if app else None

    def click(pid, name, role="button"):
        def invoke():
            node = find(pid, role, name)
            if not node:
                return False
            if not node.get_state_set().contains(Atspi.StateType.ENABLED):
                return False
            action = node.get_action_iface()
            assert action and action.get_n_actions() > 0, f"No action on {name}"
            actions = [action.get_action_name(index) for index in range(action.get_n_actions())]
            result["button_actions"] = actions
            index = next((index for index, value in enumerate(actions) if value in ["click", "press"]), 0)
            return action.do_action(index)
        wait_for(invoke)

    try:
        if args.xvfb:
            display_path = root / "xvfb-display"
            with open(display_path, "w") as display_file:
                log = open(root / "xvfb.log", "w")
                files.append(log)
                processes.append(subprocess.Popen([str(args.xvfb), "-displayfd", str(display_file.fileno()), "-screen", "0", "1600x1200x24", "-nolisten", "tcp"],
                                                  env=env, pass_fds=(display_file.fileno(),), stdout=log, stderr=log))
                number = wait_for(lambda: display_path.read_text().strip(), 30)
            assert number.isdigit()
            env["DISPLAY"] = f":{number}"
            env.pop("WAYLAND_DISPLAY", None)
            env.pop("WAYLAND_SOCKET", None)
            env["GDK_BACKEND"] = "x11"
            env["XDG_SESSION_TYPE"] = "x11"
            result["display_backend"] = "isolated X11"
        else:
            result["display_backend"] = "desktop session"
        bus = subprocess.run(["dbus-daemon", "--session", "--fork", "--print-address=1", "--print-pid=1"],
                             check=True, capture_output=True, text=True).stdout.splitlines()
        bus_pid = int(bus[1])
        env["AT_SPI_BUS_ADDRESS"] = os.environ["AT_SPI_BUS_ADDRESS"] = bus[0]
        registry = next((path for path in ["/usr/lib/at-spi2-registryd", "/usr/libexec/at-spi2-registryd"] if Path(path).exists()), None)
        assert registry, "AT-SPI registry executable not found"
        launch([registry], "registry")
        # Only the private session's accessibility service is enabled.
        subprocess.run(["gdbus", "call", "--session", "--dest", "org.a11y.Bus", "--object-path", "/org/a11y/bus",
                        "--method", "org.freedesktop.DBus.Properties.Set", "org.a11y.Status", "IsEnabled", "<true>"],
                       env=env, check=True, capture_output=True)
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            port = sock.getsockname()[1]
        pm("config", "--server-port", str(port))
        config_path = root / "pm-config/config.toml"
        config_text, replacements = re.subn(r"(?m)^scale = \d+$", f"scale = {args.scale}", config_path.read_text())
        assert replacements == 1, "Missing private desktop scale setting"
        config_path.write_text(config_text)
        result["interface_scale"] = args.scale
        pm("start")
        started = True
        if runtime:
            config = root / "speech-config"
            config.mkdir(exist_ok=True)
            (config / "speechd.conf").write_text(f'LogLevel 3\nDefaultLanguage "en"\nAddModule "espeak-ng" "sd_espeak-ng" "{runtime}/etc/speech-dispatcher/modules/espeak-ng.conf"\nDefaultModule "espeak-ng"\nAudioOutputMethod "pulse"\n')
            env["SPEECHD_ADDRESS"] = f"unix_socket:{root}/speechd.sock"
            launch([str(runtime / "usr/bin/speech-dispatcher"), "-s", "-t", "0", "-S", str(root / "speechd.sock"),
                    "-C", str(config), "-m", str(runtime / "usr/lib/speech-dispatcher/speech-dispatcher-modules"),
                    "-P", str(root / "speechd.pid"), "-L", str(root)], "speech")
            wait_for(lambda: (root / "speechd.sock").exists(), 10)
        reader = launch([orca, "--debug-file", str(root / "orca-debug.log")], "orca-console")
        def reader_ready():
            path = root / "orca-debug.log"
            return path.exists() and "Starting Atspi main event loop" in path.read_text(errors="replace")
        wait_for(reader_ready, 40)
        result["checks"]["orca_ready"] = True
        reference = root / "reference.py"
        reference.write_text('import gi\ngi.require_version("Gtk", "3.0")\nfrom gi.repository import Gtk\nw=Gtk.Window(title="Password Manager accessibility reference")\nb=Gtk.Button(label="Synthetic reference control"); w.add(b)\nw.show_all(); Gtk.main()\n')
        ref = launch([sys.executable, str(reference)], "reference", dict(env, GTK_MODULES="atk-bridge", NO_AT_BRIDGE="0"))
        gui = launch([binary, "gui"], "gui")
        wait_for(lambda: find(ref.pid, "button", "Synthetic reference control"))
        result["checks"]["reference_tree"] = True
        wait_for(lambda: find(gui.pid, "button", "Create your first vault"), 45)
        result["checks"]["named_gui_controls"] = True
        wait_for(lambda: application(gui.pid).get_parent())
        result["checks"]["application_desktop_parent"] = True
        click(gui.pid, "Create your first vault")
        result["checks"]["native_button_action_dispatched"] = True
        master = wait_for(lambda: find(gui.pid, "password text", "Enter master password"))
        result["checks"]["native_button_action"] = True
        address = None
        def own_focus():
            window = json.loads(subprocess.check_output(["hyprctl", "-j", "activewindow"]))
            return window.get("pid") == gui.pid
        if args.xvfb:
            def own_xwindow():
                reply = subprocess.run(["xdotool", "search", "--onlyvisible", "--pid", str(gui.pid), "--name", "^Password Manager$"], env=env, capture_output=True, text=True)
                return reply.stdout.strip().splitlines()[0] if reply.returncode == 0 and reply.stdout.strip() else None
            xwindow = wait_for(own_xwindow)
            subprocess.run(["xdotool", "windowfocus", "--sync", xwindow], env=env, check=True, capture_output=True)
            result["x11_focus_verified"] = subprocess.check_output(["xdotool", "getwindowfocus"], env=env, text=True).strip() == xwindow
            assert result["x11_focus_verified"]
            result["checks"]["compositor_focus"] = True
        elif shutil.which("hyprctl"):
            def own_window():
                clients = json.loads(subprocess.check_output(["hyprctl", "-j", "clients"]))
                return next((window.get("address") for window in clients if window.get("pid") == gui.pid and window.get("mapped")), None)
            address = wait_for(own_window)
            assert re.fullmatch(r"0x[0-9a-fA-F]+", address)
            version = subprocess.check_output(["hyprctl", "version"], text=True)
            match = re.search(r"Hyprland (\d+)\.(\d+)", version)
            lua = bool(match and (int(match[1]), int(match[2])) >= (0, 55))
            focus_command = [f'hl.dsp.focus({{window = "address:{address}"}})'] if lua else ["focuswindow", f"address:{address}"]
            reply = subprocess.run(["hyprctl", "dispatch", *focus_command], check=True, capture_output=True)
            result["compositor_focus_reply"] = reply.stdout.decode(errors="replace")
            wait_for(own_focus)
            result["checks"]["compositor_focus"] = True
        assert master.get_component_iface().grab_focus()
        def master_focused():
            master.clear_cache()
            return master.get_state_set().contains(Atspi.StateType.FOCUSED)
        wait_for(master_focused)
        result["checks"]["native_focus_action"] = True
        def master_announced():
            debug = (root / "orca-debug.log").read_text(errors="replace")
            return any("SPEECH OUTPUT:" in line and "Enter master password" in line for line in debug.splitlines())
        wait_for(master_announced)
        result["checks"]["orca_announced_password_field"] = True
        if args.xvfb or (shutil.which("hyprctl") and shutil.which("wtype")):
            if args.xvfb:
                subprocess.run(["xdotool", "type", "--clearmodifiers", "--delay", "1", "synthetic-native-protected-value"], env=env, check=True)
            else:
                wait_for(own_focus)
                subprocess.run(["wtype", "synthetic-native-protected-value"], check=True)
            wait_for(lambda: find(gui.pid, "label", "Confirm master password"))
            time.sleep(0.5)
            exposed = [{"role": node.get_role_name(), "name": node.get_name(),
                        "text": Atspi.Text.get_text(node.get_text_iface(), 0, -1) if node.get_text_iface() else ""}
                       for node in nodes(application(gui.pid))]
            assert "synthetic-native-protected-value" not in json.dumps(exposed)
            protected_text = master.get_text_iface()
            assert protected_text is None or Atspi.Text.get_character_count(protected_text) == 0
            result["checks"]["protected_keyboard_input"] = True
            if args.xvfb:
                subprocess.run(["xdotool", "key", "--clearmodifiers", "Tab"], env=env, check=True)
            else:
                tab_command = [f'hl.dsp.send_shortcut({{mods = "", key = "Tab", window = "address:{address}"}})'] if lua else ["sendshortcut", f",Tab,address:{address}"]
                subprocess.run(["hyprctl", "dispatch", *tab_command], check=True, capture_output=True)
            wait_for(lambda: not master_focused())
            result["checks"]["native_tab_navigation"] = True
            if args.xvfb:
                subprocess.run(["xdotool", "type", "--clearmodifiers", "--delay", "1", "synthetic-native-protected-value"], env=env, check=True)
            else:
                wait_for(own_focus)
                subprocess.run(["wtype", "synthetic-native-protected-value"], check=True)
            def matching_passwords():
                button = find(gui.pid, "button", "Create vault")
                return button and button.get_state_set().contains(Atspi.StateType.ENABLED)
            wait_for(matching_passwords)
            result["checks"]["native_password_confirmation"] = True
        else:
            result["limitations"].append("Native typing/Tab check requires Hyprland and wtype.")
        public_input = wait_for(lambda: find(gui.pid, ["text", "entry"], "Vault name"))
        text_interface = public_input.get_text_iface()
        assert text_interface and Atspi.Text.get_text(text_interface, 0, -1) == "Personal vault"
        assert public_input.get_component_iface().grab_focus()
        def public_focused():
            public_input.clear_cache()
            return public_input.get_state_set().contains(Atspi.StateType.FOCUSED)
        wait_for(public_focused)
        wait_for(lambda: text_interface.get_caret_offset() == len("Personal vault"))
        assert text_interface.set_caret_offset(0)
        wait_for(lambda: text_interface.get_caret_offset() == 0)
        result["checks"]["native_text_value_and_caret"] = True
        click(gui.pid, "Settings")
        wait_for(lambda: find(gui.pid, "combo box", "Color theme"))
        settings_button = find(gui.pid, "button", "Settings")
        assert settings_button.get_state_set().contains(Atspi.StateType.SELECTED)
        result["checks"]["selected_navigation_state"] = True
        click(gui.pid, "Color theme", "combo box")
        click(gui.pid, "Light", "menu item")
        wait_for(lambda: find(gui.pid, "label", "Unsaved settings · Ctrl/Cmd+S to save"))
        result["checks"]["native_dropdown_selection"] = True
        click(gui.pid, "Save settings")
        def saved_announced():
            debug = (root / "orca-debug.log").read_text(errors="replace")
            return any("SPEECH OUTPUT:" in line and "Settings saved" in line for line in debug.splitlines())
        wait_for(saved_announced)
        result["checks"]["orca_announced_save_completion"] = True
        if args.xvfb:
            subprocess.run(["xdotool", "windowsize", xwindow, "480", "480"], env=env, check=True)
            def resized_category():
                node = find(gui.pid, "combo box", "Settings category")
                if not node:
                    return False
                bounds = node.get_component_iface().get_extents(Atspi.CoordType.WINDOW)
                return bounds.x >= 0 and bounds.x + bounds.width <= 481
            wait_for(resized_category)
            click(gui.pid, "Settings category", "combo box")
            click(gui.pid, "Passwords", "menu item")
            visited = []
            result["tabbed_controls"] = visited
            def focused_control():
                return next((node for node in nodes(application(gui.pid)) if node.get_state_set().contains(Atspi.StateType.FOCUSED)), None)
            for _ in range(20):
                previous = focused_control()
                name = previous.get_name() if previous else ""
                subprocess.run(["xdotool", "key", "--clearmodifiers", "Tab"], env=env, check=True)
                control = wait_for(lambda: (node if (node := focused_control()) and node.get_name() != name else None))
                def visible_focus():
                    node = focused_control()
                    if not node:
                        return False
                    bounds = node.get_component_iface().get_extents(Atspi.CoordType.WINDOW)
                    return bounds.y >= 0 and bounds.y + bounds.height <= 481
                wait_for(visible_focus)
                visited.append(control.get_name())
            result["checks"]["native_focus_scrolls_into_view"] = True
            result["tabbed_controls"] = visited
        # Exercise the real multiline editor in an isolated synthetic vault.
        key = root / "synthetic-vault.key"
        if args.xvfb:
            subprocess.run(["xdotool", "windowsize", xwindow,
                            str(1060 * args.scale // 100), str(760 * args.scale // 100)], env=env, check=True)
            time.sleep(0.5)
        pm("new", "--key", str(key))
        pm("unlock", "--key", str(key), "--timeout", "0")
        click(gui.pid, "Vault")
        wait_for(lambda: find(gui.pid, "button", "Refresh items"))
        time.sleep(0.5)
        click(gui.pid, "Add item")
        wait_for(lambda: find(gui.pid, ["entry", "text"], "Item name"))
        def reach_notes():
            node = find(gui.pid, ["entry", "text"], "Private notes")
            if node:
                return node
            if args.xvfb:
                subprocess.run(["xdotool", "key", "--clearmodifiers", "Tab"], env=env, check=True)
            else:
                subprocess.run(["hyprctl", "dispatch", *tab_command], check=True, capture_output=True)
            return None
        notes = wait_for(reach_notes)
        result["phase"] = "multiline focus"
        assert notes.get_component_iface().grab_focus()
        def notes_focused():
            notes.clear_cache()
            return notes.get_state_set().contains(Atspi.StateType.FOCUSED)
        wait_for(notes_focused)
        result["phase"] = "multiline keyboard input"
        if args.xvfb:
            subprocess.run(["xdotool", "type", "--clearmodifiers", "--delay", "1", "first"], env=env, check=True)
            subprocess.run(["xdotool", "key", "--clearmodifiers", "Return"], env=env, check=True)
            subprocess.run(["xdotool", "type", "--clearmodifiers", "--delay", "1", "second"], env=env, check=True)
        else:
            wait_for(own_focus)
            subprocess.run(["wtype", "first", "-k", "Return", "second"], check=True)
        def note_value():
            node = find(gui.pid, ["entry", "text"], "Private notes")
            iface = node.get_text_iface() if node else None
            value = Atspi.Text.get_text(iface, 0, -1) if iface else None
            result["multiline_observed_value"] = value
            return iface if value == "first\nsecond" else None
        note_text = wait_for(note_value)
        result["phase"] = "multiline line navigation"
        line = note_text.get_string_at_offset(8, Atspi.TextGranularity.LINE)
        assert line.content == "second", f"Wrong multiline line at offset 8: {line.content!r}"
        result["phase"] = "multiline caret and selection"
        assert note_text.set_caret_offset(8)
        wait_for(lambda: note_text.get_caret_offset() == 8)
        assert note_text.add_selection(1, 4)
        wait_for(lambda: note_text.get_n_selections() == 1)
        result["checks"]["native_multiline_text_caret_selection"] = True
        if args.xvfb:
            # A real pointer click at the exported physical bounds must hit
            # the named button, including at enlarged interface scales.
            target = find(gui.pid, "button", "Settings")
            bounds = target.get_component_iface().get_extents(Atspi.CoordType.WINDOW)
            subprocess.run(["xdotool", "mousemove", "--window", xwindow,
                            str(bounds.x + bounds.width // 2), str(bounds.y + bounds.height // 2),
                            "click", "1"], env=env, check=True)
            wait_for(lambda: find(gui.pid, "combo box", "Settings category"))
            result["checks"]["native_pointer_matches_accessible_bounds"] = True
        time.sleep(2)
        assert reader.poll() is None, "Orca exited during the check"
        result["checks"]["orca_running"] = True
        result["gui_nodes"] = [{"role": node.get_role_name(), "name": node.get_name()} for node in nodes(application(gui.pid))]
        result["passed"] = True
        result["phase"] = "complete"
    except Exception as error:
        result.update(passed=False, error=str(error))
        if isinstance(error, subprocess.CalledProcessError):
            result["command_error"] = (error.stderr or error.stdout or b"").decode(errors="replace")
        try:
            if "gui" in locals() and application(gui.pid):
                result["gui_nodes"] = [{"role": node.get_role_name(), "name": node.get_name()} for node in nodes(application(gui.pid))]
                if "master" in locals():
                    master.clear_cache()
                    result["master_states"] = [str(state) for state in master.get_state_set().get_states()]
        except GLib.Error:
            pass
    finally:
        # Stop app/reader before their accessibility registry and private bus.
        for process in reversed(processes):
            if process.poll() is None:
                process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
        if started:
            pm("kill")
        if bus_pid:
            os.kill(bus_pid, signal.SIGTERM)
        for log in files:
            log.close()
        (root / "result.json").write_text(json.dumps(result, indent=2))
        print(json.dumps(result, indent=2))
        print(f"Evidence: {root}")
    return 0 if result.get("passed") else 1


if __name__ == "__main__":
    sys.exit(main())
