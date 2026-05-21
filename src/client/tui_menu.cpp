#include "../../include/tui_menu.h"
#include "ftxui/component/component.hpp"
#include "ftxui/component/screen_interactive.hpp"
#include "ftxui/dom/elements.hpp"
#include <algorithm>
#include <iostream>
#include <sstream>

Action show_numeric_menu() {
    int intention = 0;
    std::cout << "\n--- MEFS Client Menu ---\n";
    std::cout << "1. Download File\n";
    std::cout << "2. Upload File\n";
    std::cout << "3. List Files\n";
    std::cout << "4. Delete File\n";
    std::cout << "5. Quit\n";
    std::cout << "Select: " << std::flush;
    while (!(std::cin >> intention)) {
        std::cin.clear();
        std::cin.ignore();
        std::cerr << "Invalid input, please try again: ";
    }
    switch (intention) {
    case 1: return Action::READ_FROM_FILESYSTEM;
    case 2: return Action::WRITE_TO_FILESYSTEM;
    case 3: return Action::LIST_FILES;
    case 4: return Action::DELETE_FILE;
    default: return Action::CONFUSION;
    }
}

MenuResult show_menu(std::vector<std::string> &output_log,
                     const std::vector<std::string> &file_list) {
    if (!isatty(STDIN_FILENO)) {
        Action a = show_numeric_menu();
        return {a, ""};
    }

    using namespace ftxui;

    std::vector<std::string> entries = {
        "Download File",
        "Upload File",
        "List Files",
        "Delete File",
        "Quit",
    };
    int selected = 0;
    std::string input_text = "";

    auto menu = Menu(&entries, &selected);
    auto input = Input(&input_text, "type here...");

    auto screen = ScreenInteractive::Fullscreen();

    auto component = Container::Vertical({
        menu,
        input,
    });

    auto renderer = Renderer(component, [&] {
        Elements lines;
        lines.push_back(text("MEFS Client") | bold | center);
        lines.push_back(separator());
        lines.push_back(menu->Render());

        if (selected == 0) {
            lines.push_back(separator());
            if (file_list.empty()) {
                lines.push_back(text("  (list files first to search)") | dim);
            } else {
                lines.push_back(text("  Search files:") | bold);
                lines.push_back(input->Render() | size(WIDTH, EQUAL, 40));
                lines.push_back(separator());
                int match_count = 0;
                for (auto &f : file_list) {
                    if (input_text.empty() ||
                        f.find(input_text) != std::string::npos) {
                        lines.push_back(text("  " + f));
                        match_count++;
                    }
                }
                if (match_count == 0 && !input_text.empty()) {
                    lines.push_back(text("  (no matches)") | dim);
                }
            }
        } else if (selected == 1 || selected == 3) {
            lines.push_back(separator());
            lines.push_back(text(selected == 1 ? "  File to upload:"
                                               : "  File to delete:") |
                            bold);
            lines.push_back(input->Render() | size(WIDTH, EQUAL, 40));
        }

        if (!output_log.empty()) {
            lines.push_back(separator());
            lines.push_back(text("Output:") | bold);
            for (auto &line : output_log) {
                if (line.empty()) continue;
                lines.push_back(text("  " + line));
            }
        }

        lines.push_back(separator());
        lines.push_back(text("  Enter=confirm  q=quit") | dim);

        return vbox(std::move(lines)) | border;
    });

    renderer |= CatchEvent([&](Event event) {
        if (event == Event::Return) {
            screen.ExitLoopClosure()();
            return true;
        }
        if (event == Event::Character('q') && !input->Focused()) {
            selected = 4;
            screen.ExitLoopClosure()();
            return true;
        }
        if (event == Event::Escape) {
            selected = 4;
            screen.ExitLoopClosure()();
            return true;
        }
        return false;
    });

    screen.Loop(renderer);

    Action action;
    switch (selected) {
    case 0: action = Action::READ_FROM_FILESYSTEM; break;
    case 1: action = Action::WRITE_TO_FILESYSTEM; break;
    case 2: action = Action::LIST_FILES; break;
    case 3: action = Action::DELETE_FILE; break;
    default: action = Action::CONFUSION; break;
    }

    return {action, input_text};
}
