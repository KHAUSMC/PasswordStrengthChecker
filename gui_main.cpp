#include <QApplication>
#include <QWidget>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QLineEdit>
#include <QPushButton>
#include <QLabel>
#include <QProgressBar>
#include <unordered_set>
#include "password_scoring.h"

static const char *bucket_name(pwcheck::Bucket b)
{
    switch (b)
    {
    case pwcheck::Bucket::Weak:
        return "Weak";
    case pwcheck::Bucket::Fair:
        return "Fair";
    case pwcheck::Bucket::Strong:
        return "Strong";
    case pwcheck::Bucket::VeryStrong:
        return "Very Strong";
    }
    return "?";
}

int main(int argc, char *argv[])
{
    QApplication app(argc, argv);

    QWidget win;
    win.setWindowTitle("Password Strength Checker");

    auto *layout = new QVBoxLayout(&win);

    // Input field
    auto *input = new QLineEdit();
    input->setPlaceholderText("Enter a password…");
    input->setEchoMode(QLineEdit::Password);

    // Score row (progress bar + labels)
    auto *row = new QHBoxLayout();
    auto *scoreBar = new QProgressBar();
    scoreBar->setRange(0, 100);
    scoreBar->setValue(0);
    scoreBar->setTextVisible(false);

    auto *scoreLbl = new QLabel("Score: 0");
    auto *bucketLbl = new QLabel("Bucket: -");

    row->addWidget(scoreBar, 1);
    row->addWidget(scoreLbl);
    row->addWidget(bucketLbl);

    // Reasons
    auto *reasonsTitle = new QLabel("<b>Reasons</b>");
    auto *reasonsLbl = new QLabel("—");
    reasonsLbl->setWordWrap(true);

    // Button

    layout->addWidget(input);
    layout->addLayout(row);
    layout->addWidget(reasonsTitle);
    layout->addWidget(reasonsLbl);

    // Blocklist & dictionary (sample sets)
    std::unordered_set<std::string> blocklist = {"password", "123456", "qwerty"};
    std::unordered_set<std::string> dictionary = {"cat", "dog", "tree", "love"};

    // Function to compute score
    auto compute = [&]
    {
        const std::string pw = input->text().toStdString();
        pwcheck::ScoreDetail r = pwcheck::score_password(pw, blocklist, dictionary);

        scoreBar->setValue(r.score);
        scoreLbl->setText(QString("Score: %1").arg(r.score));
        bucketLbl->setText(QString("Bucket: %1").arg(bucket_name(r.bucket)));

        // color the bar
        QString style;
        switch (r.bucket)
        {
        case pwcheck::Bucket::Weak:
            style = "QProgressBar::chunk{background:#d9534f;}";
            break;
        case pwcheck::Bucket::Fair:
            style = "QProgressBar::chunk{background:#f0ad4e;}";
            break;
        case pwcheck::Bucket::Strong:
            style = "QProgressBar::chunk{background:#5bc0de;}";
            break;
        case pwcheck::Bucket::VeryStrong:
            style = "QProgressBar::chunk{background:#5cb85c;}";
            break;
        }
        scoreBar->setStyleSheet(style);

        QString reasons;
        if (r.reasons.empty())
        {
            reasons = "Looks good—no specific warnings.";
        }
        else
        {
            for (const auto &msg : r.reasons)
                reasons += "• " + QString::fromStdString(msg) + "\n";
        }
        reasonsLbl->setText(reasons.trimmed());
    };

    QObject::connect(input, &QLineEdit::textChanged, [&](const QString &)
                     { compute(); });

    win.resize(520, 260);
    win.show();
    return app.exec();
}
