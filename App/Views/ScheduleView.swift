import SwiftUI

struct ScheduleView: View {
    @EnvironmentObject private var scheduler: ScanScheduler

    private let weekdays = Calendar.current.weekdaySymbols

    var body: some View {
        Page {
            PageHeader(title: "Scheduled Scans", subtitle: "Let Agamemnon check your Mac regularly, without you having to remember.")

            Card {
                VStack(alignment: .leading, spacing: 16) {
                    SettingRow(symbol: "calendar.badge.clock", title: "Scan on a schedule",
                               detail: scheduler.enabled ? nextRunText : "Off",
                               color: scheduler.enabled ? Theme.success : Theme.textSecondary) {
                        Toggle("", isOn: $scheduler.enabled).toggleStyle(.switch).labelsHidden()
                    }

                    if scheduler.enabled {
                        Divider().overlay(Theme.stroke)
                        Grid(alignment: .leading, horizontalSpacing: 18, verticalSpacing: 14) {
                            GridRow {
                                label("Scan type")
                                Picker("", selection: $scheduler.kind) {
                                    Text("Quick Scan").tag(ScanKind.quick)
                                    Text("Full Scan").tag(ScanKind.full)
                                }
                                .pickerStyle(.segmented).labelsHidden().frame(width: 240)
                            }
                            GridRow {
                                label("How often")
                                Picker("", selection: $scheduler.frequency) {
                                    ForEach(ScanScheduler.Frequency.allCases) { Text($0.title).tag($0) }
                                }
                                .pickerStyle(.segmented).labelsHidden().frame(width: 240)
                            }
                            if scheduler.frequency == .weekly {
                                GridRow {
                                    label("Day")
                                    Picker("", selection: $scheduler.weekday) {
                                        ForEach(1...7, id: \.self) { day in Text(weekdays[day - 1]).tag(day) }
                                    }
                                    .labelsHidden().frame(width: 180)
                                }
                            }
                            GridRow {
                                label("Time")
                                DatePicker("", selection: $scheduler.time, displayedComponents: .hourAndMinute)
                                    .labelsHidden().frame(width: 120)
                            }
                        }
                    }
                    if let last = scheduler.lastRun {
                        Text("Last scheduled scan: \(last.formatted(date: .abbreviated, time: .shortened))")
                            .font(.system(size: 11)).foregroundStyle(Theme.textTertiary)
                    }
                }
            }

            Card {
                VStack(alignment: .leading, spacing: 10) {
                    SettingRow(symbol: "power", title: "Open Agamemnon at login",
                               detail: "Scheduled scans and real-time protection run while Agamemnon is open in the menu bar. Closing the window keeps it running.") {
                        Toggle("", isOn: Binding(get: { scheduler.launchAtLogin },
                                                 set: { scheduler.setLaunchAtLogin($0) }))
                            .toggleStyle(.switch).labelsHidden()
                    }
                    if let error = scheduler.loginItemError {
                        Notice(symbol: "exclamationmark.triangle", text: error)
                    }
                }
            }
        }
        .onAppear { scheduler.refreshLoginItem() }
    }

    private var nextRunText: String {
        guard let next = scheduler.nextRun else { return "Not scheduled" }
        return "Next \(scheduler.kind.title.lowercased()): \(next.formatted(date: .complete, time: .shortened))"
    }

    private func label(_ text: String) -> some View {
        Text(text).font(.system(size: 13, weight: .medium)).foregroundStyle(Theme.textSecondary)
    }
}
