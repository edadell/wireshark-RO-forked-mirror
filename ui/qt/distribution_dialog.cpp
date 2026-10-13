/* distribution_dialog.cpp
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include "distribution_dialog.h"

#include <cmath>

#include <QTreeWidget>
#include <QTreeWidgetItem>

#include <epan/packet.h>
#include <epan/strutil.h>
#include <epan/tap.h>
#include <epan/epan_dissect.h>

#include "main_application.h"
#include "ui/qt/ui_tap_parameter_dialog.h"

// To do:
// - checkbox for 'Limit to display filter'
// - clarify/document why total of percentages may be more than 100
// - handle marginal distributions values

enum {
    col_fvalue_,
    col_counter_,
    col_percent_
};

/*
 * Some aggregated FTs as if they were coming from an FT_IS_ macro.
 * Helps sorting the Field Name column.
 */
enum {
    AGG_FT_INT,
    AGG_FT_STRING,
    AGG_FT_IP
};

struct _tap_elts {
    int count;
    QTreeWidgetItem *item;
};

/* map key definition (key width and "modalities" (values) seen */
typedef struct {
    guint n;
    const char **modalities;
} dist_key_t;

/* compute a hash with the good old 31 multiplier */
static guint dist_key_hash(gconstpointer p)
{
    const dist_key_t *k = (const dist_key_t *) p;
    guint h = 0;

    for (guint i = 0; i < k->n; i++)
        h = h * 31 + wmem_str_hash(k->modalities[i]);

    return h;
}

/* hash key equality */
static gboolean dist_key_equal(gconstpointer a, gconstpointer b)
{
    const dist_key_t *ka = (const dist_key_t *) a;
    const dist_key_t *kb = (const dist_key_t *) b;

    if (ka->n != kb->n)
        return FALSE;

    for (guint i = 0; i < ka->n; i++) {
        if (strcmp(ka->modalities[i], kb->modalities[i]) != 0)
            return FALSE;
    }

    return TRUE;
}

/* Increment the observation counter for a given key.
 * Insert a new key when necessary.
 */
static void dist_map_add_observation(wmem_map_t *map, wmem_allocator_t *alloc,
                           const char *const *vals, guint n)
{
    // key to look for in the map
    dist_key_t probe;
    probe.n = n;
    probe.modalities = (const char **) vals;

    guint64 *count = (guint64 *) wmem_map_lookup(map, &probe);
    if (count) {
        (*count)++;
        return;
    }

    /* key wasn't found, create one and add it to the map */
    dist_key_t *key = wmem_new(alloc, dist_key_t);
    const char **copy = (const char **) wmem_alloc(alloc, n * sizeof(const char *));
    for (guint i = 0; i < n; i++)
        copy[i] = wmem_strdup(alloc, vals[i]);
    key->n = n;
    key->modalities = copy;

    count = wmem_new(alloc, guint64);
    *count = 1;

    wmem_map_insert(map, key, count);
}

/*
struct DumpState {
    guint64 sum;       // all
    guint   printed;   // lines already printed
    guint   limit;     // display limit
};

static void dist_map_dump_entry(gpointer key, gpointer value, gpointer user_data)
{
    const dist_key_t *k = (const dist_key_t *) key;
    const guint64 *count = (const guint64 *) value;
    DumpState *st = (DumpState *) user_data;

    st->sum += *count;
    if (st->printed >= st->limit) return;
    st->printed++;

    printf("  [");
    //for (guint i = 0; i < k->variable_count; i++)
    for (guint i = 0; i < k->n; i++)
        printf("%s%s", i ? " | " : "", k->modalities[i]);
    printf("] -> %llu\n", (unsigned long long) *count);
}*/

/*
 * Return true if the given field supports this distribution stats, false otherwise.
 */
static int
hfi_supports_distribution(const header_field_info *hfi) {
    if (FT_IS_STRING(hfi->type)) {
        return FT_STRING;
    }
    else if(FT_IS_INTEGER(hfi->type))  {
        return FT_INT32;
    }
    else {
        switch (hfi->type) {
        case FT_IPv4:
        case FT_IPv6:
            return FT_IPv4;
        default:
            /* not supported FT, return false */
            return 0;
        }
    }
}

static gboolean
alwaysTrue(void *key _U_, void *value _U_, void *data _U_) {
    return true;
}

/* Normalized Shannon */
double normalized_shannon(const int *freq, size_t n_symbols, size_t total) {

    /* ensure we have enough data or there's not much sense to compute */
    if (total == 0 || n_symbols < 2) {
        return 0.0;
    }

    double H = 0.0;
    for (size_t i = 0; i < n_symbols; i++) {
        if (freq[i] == 0) continue;
        double p = (double)freq[i] / (double)total;
        H -= p * log2(p);
    }

    return H / log2((double)n_symbols);
}

/* Append a string to a list which stores only unique values (like QSet, but lighter) */
static void append_unique(QList<const char *> &list, const char *value)
{
    for (const char *v : list) {
        if (strcmp(v, value) == 0) return;
    }
    list.append(value);
}

/* Limit to 4 variables maximum, and 10k rows displayed.
 * XXX - Change this if required
 */
static constexpr int dist_max_variables = 4;
static constexpr int dist_max_rows = 10000;

class DistributionStatTreeWidgetItem : public QTreeWidgetItem
{
public:
    DistributionStatTreeWidgetItem(QTreeWidget *parent, const QStringList &modalities,
                                   const QList<int> &field_types) :
        QTreeWidgetItem(parent), modalities_(modalities), field_types_(field_types)
    {
        for (int i = 0; i < modalities_.size(); i++)
            setText(i, modalities_[i]);
        count_ = static_cast<int>(modalities_.size());
    }

    int counterColumn() const { return static_cast<int>(modalities_.size()); }
    int percentColumn() const { return static_cast<int>(modalities_.size()) + 1; }

    bool isMatch(const QStringList &modalities) const { return modalities == modalities_; }

    bool operator<(const QTreeWidgetItem &other) const override
    {
        const DistributionStatTreeWidgetItem *o =
            static_cast<const DistributionStatTreeWidgetItem *>(&other);
        const int col = treeWidget()->sortColumn();
        if (col < 0) return QTreeWidgetItem::operator<(other);

        switch (columnKind(col)) {
        case ColCount:
            return count_ < o->count_;
        case ColPercent:
            return percent_ < o->percent_;
        case ColModality:
            /* typically sorting based on an aggregate FT value */
            switch (field_types_[col]) {
            case AGG_FT_INT:
                return modalities_[col].toLongLong() < o->modalities_[col].toLongLong();

            /* no specific handling for Strings and IPs,
             * though the latter would benefit of a better sorting (XXX - same in endpoints/conversations ) */
            case AGG_FT_STRING:
            case AGG_FT_IP:
            default:
                break;
            }
            break;
        }
        return QTreeWidgetItem::operator<(other);
    }

    void update(guint64 new_count) {
        count_ = new_count;
        setText(counterColumn(), QString::number(count_));
        setTextAlignment(counterColumn(), Qt::AlignRight);
    }

    void updatePercentage(guint64 total) {
        percent_ = total ? count_ * 100.0 / total : 0.0;
        setText(percentColumn(), QString::number(percent_, 'f', 2));
        setTextAlignment(percentColumn(), Qt::AlignRight);
        setData(percentColumn(), Qt::UserRole, percent_);
    }

    QList<QVariant> rowData() const {
        QList<QVariant> row;
        for (const QString &m : modalities_) row << m;
        row << QVariant::fromValue<qulonglong>(count_) << percent_;
        return row;
    }

    QString filterExpression(const QStringList &field_names, const QList<bool> &quotes) const {
        QStringList terms;
        for (int i = 0; i < modalities_.size(); i++) {
            terms << (quotes[i] ? QStringLiteral("%1==\"%2\"") : QStringLiteral("%1==%2"))
                         .arg(field_names[i], modalities_[i]);
        }
        return terms.join(QStringLiteral(" && "));
    }

    guint64 count() const { return count_; }
    double percent() const { return percent_; }

private:
    QStringList modalities_;
    QList<int>  field_types_;
    guint64     count_ = 0;
    double      percent_ = 0;

    enum ColumnKind { ColModality, ColCount, ColPercent };

    ColumnKind columnKind(int col) const {
        if (col == counterColumn()) return ColCount;
        if (col == percentColumn()) return ColPercent;
        return ColModality;
    }

};

DistributionDialog::DistributionDialog(QWidget &parent, CaptureFile &cf, const QString &filter) :
    TapParameterDialog(parent, cf, 0),
    packet_count_(0),
    observations_(0),
    displayFilter_(""), // no default value when opening from the stats menu
    needsQuotes_(0)
{
    hf_index_ = -1;
    allocator = wmem_allocator_new(WMEM_ALLOCATOR_BLOCK);
    fvalues_map = wmem_map_new(allocator, wmem_str_hash, g_str_equal);
    map_ = wmem_map_new(allocator, dist_key_hash, dist_key_equal);

    if (!registerTapListener("frame",
                             this,
                             displayFilter_.toUtf8().data(),
                             TL_REQUIRES_PROTO_TREE,
                             tapReset,
                             tapPacket,
                             tapDraw)) {
        tap_registered_ = false;
        return;
    }
    else {
        tap_registered_ = true;
    }

    setWindowSubtitle(tr("Field Values Distribution"));
    loadGeometry(parent.width() * 4 / 5, parent.height() * 3 / 4, "DistributionDialog");

    /* Override the inherited Display Filter label */
    getUI()->label->setText("Distribution Field");

    QStringList header_labels = QStringList()
            << tr("Field Value") << tr("Occurrences") << tr("Percent");
    statsTreeWidget()->setHeaderLabels(header_labels);

    for (int col = 0; col < statsTreeWidget()->columnCount(); col++) {
        if (col == col_fvalue_ ) continue;
        statsTreeWidget()->headerItem()->setTextAlignment(col, Qt::AlignRight);
    }

    /* override the default filter behavior (validation, background color) */
    DisplayFilterEdit *edit = filterEdit();
    edit->disableAutomaticValidation();
    connect(edit, &QLineEdit::textChanged, this, &DistributionDialog::onFilterTextChanged);

    onFilterTextChanged(edit->text());

    // Set handler for when display filter string is changed.
    connect(this, SIGNAL(updateFilter(QString)),
            this, SLOT(filterUpdated(QString)));
    connect(this, SIGNAL(updateFilter(QString)),
            this, SLOT(updateLabels()));

    /*connect(applyFilterButton(), &QPushButton::clicked,
            this, &DistributionDialog::updateSelectedFieldsAndHomonyms);*/

    addFilterActions();

    if (!filter.isEmpty()) {
        setDisplayFilter(filter);
    }
}

DistributionDialog::~DistributionDialog()
{
    wmem_destroy_allocator(allocator);
}

void DistributionDialog::updateLabels()
{
    /* update the window subtitle */
    setWindowSubtitle(tr("Distribution:") + displayFilter());
}

/*
 * Inherited buttons behavior,
 * overloaded with the named field(s) type(s) check to decide if conditions
 * for calculating the distributions are met.
 * As widely accepted in the distributions literature, the ',' char is used
 * as a delimitor in a multiple fields distribution.
 * Note this is an internal delimitor to this dialog only,
 * and not compatible with the display filter syntax.
 */

void DistributionDialog::updateWidgets()
{
    /*printf("updateWidgets: this=%p variables=%lld pending=%lld\n",
       (void *) this, (long long) variables_.size(), (long long) pending_variables_.size()); */

    QList<const header_field_info *> hfis;
    //bool fields_ok = parseFields(displayFilter(), hfis);
    const bool fields_ok = !pending_variables_.isEmpty() && pending_text_ == displayFilter();

    bool edit_enable = true;
    bool apply_enable = fields_ok;
    if (file_closed_ || !cap_file_.isValid()) {
        edit_enable = false;
        apply_enable = false;
    }

    getUI()->displayFilterLineEdit->setEnabled(edit_enable);
    getUI()->applyFilterButton->setEnabled(apply_enable);

    WiresharkDialog::updateWidgets();
}

void DistributionDialog::onFilterTextChanged(const QString &text)
{
    filterEdit()->setSyntaxState(checkInput(text));
    updateWidgets();
}

void DistributionDialog::tapRemoveAll(void *ws_dlg_ptr)
{
    DistributionDialog *ws_dlg = static_cast<DistributionDialog *>(ws_dlg_ptr);
    if (!ws_dlg) return;

    if (!ws_dlg->fvalues_map) return;

    wmem_map_foreach_remove(ws_dlg->fvalues_map, alwaysTrue, NULL);
    wmem_map_foreach_remove(ws_dlg->map_, alwaysTrue, NULL);
}

void DistributionDialog::tapReset(void *ws_dlg_ptr)
{
    DistributionDialog *ws_dlg = static_cast<DistributionDialog *>(ws_dlg_ptr);
    if (!ws_dlg) return;

    tapRemoveAll(ws_dlg_ptr);
    ws_dlg->statsTreeWidget()->clear();
    ws_dlg->packet_count_ = 0;
    ws_dlg->observations_ = 0;

    ws_dlg->map_ = wmem_map_new(ws_dlg->allocator, dist_key_hash, dist_key_equal);
}


tap_packet_status DistributionDialog::tapPacket(void *tap_data, _packet_info *, epan_dissect_t *edt, const void *dummy _U_, tap_flags_t)
{
    DistributionDialog *ws_dlg = static_cast<DistributionDialog *>(tap_data);

    // ensure the tap dfilter was consistently managed
    if(!edt) {
        return TAP_PACKET_FAILED;
    }

    const int variable_count = static_cast<int>(ws_dlg->variables_.size());

    // find all modalities of the given fields
    QList<QList<const char *>> found(variable_count);
    for (int i = 0; i < variable_count; i++) {

        /* all homonyms of this hf (typically ip.addr doesn't come alone) */
        for (int hf : ws_dlg->variables_[i].hf_indices) {
            GPtrArray *gp = proto_get_finfo_ptr_array(edt->tree, hf);
            if (!gp) continue;

            /* all occurences of this hf (typically ip.addr doesn't come alone) */
            for (guint j = 0; j < gp->len; j++) {
                field_info *fi = (field_info *) g_ptr_array_index(gp, j);
                const char *s = fvalue_to_string_repr(ws_dlg->allocator, fi->value, FTREPR_DISPLAY,
                                                      fi->hfinfo->display);
                append_unique(found[i], s);
            }
        }
        /* while unexpected (filter built over '&&'), ensure we would ignore packets not containing the given field */
        if (found[i].isEmpty()) return TAP_PACKET_DONT_REDRAW;
    }

    QList<int> idx(variable_count, 0);
    QList<const char *> combo(variable_count);
    for (;;) {
        for (int i = 0; i < variable_count; i++) combo[i] = found[i][idx[i]];
        dist_map_add_observation(ws_dlg->map_, ws_dlg->allocator, combo.constData(), variable_count);
        ws_dlg->observations_++;

        int k = variable_count - 1;                              // incrément « odomètre »
        while (k >= 0 && ++idx[k] == found[k].size()) { idx[k] = 0; k--; }
        if (k < 0) break;
    }

    /* percentages tracking */
    ws_dlg->packet_count_++;

    return TAP_PACKET_REDRAW;
}

void DistributionDialog::insertOccurence(void *key _U_, void *value, void *user_data) {
    wmem_array_t *arr = static_cast<wmem_array_t *>(user_data);
    wmem_array_append(arr, &static_cast<_tap_elts *>(value)->count, 1);
}

void DistributionDialog::setFilterQuotes(int type_filter) {
    switch (type_filter) {
    case FT_STRING:
        needsQuotes_ = true;
        break;
    default:
        needsQuotes_ = false;
        break;
    }
}

/* raw types are converted to their aggregate type, or defaults to String */
void DistributionDialog::setFieldType(int raw_type) {

    if (FT_IS_STRING(raw_type)) {
        field_type_ = AGG_FT_STRING;
    }
    else if (FT_IS_INTEGER(raw_type)) {
        field_type_ = AGG_FT_INT;
    }
    else {
        switch (raw_type) {
        case FT_IPv4:
        case FT_IPv6:
            field_type_ = AGG_FT_IP;
            break;
        default:
            field_type_ = AGG_FT_STRING;
        }
    }
}

struct DrawEntry {
    const dist_key_t *key;
    guint64           count;
};

static void dist_map_collect(gpointer key, gpointer value, gpointer user_data)
{
    QList<DrawEntry> *out = static_cast<QList<DrawEntry> *>(user_data);
    out->append(DrawEntry{ (const dist_key_t *) key, *(const guint64 *) value });
}

void DistributionDialog::tapDraw(void *ws_dlg_ptr)
{
    DistributionDialog *ws_dlg = static_cast<DistributionDialog *>(ws_dlg_ptr);
    if (!ws_dlg || !ws_dlg->map_ || ws_dlg->variables_.isEmpty()) return;

    QTreeWidget *tree = ws_dlg->statsTreeWidget();

    /* 1. collect all entries of the map, sorted by decreasing count */
    QList<DrawEntry> entries;
    entries.reserve(wmem_map_size(ws_dlg->map_));
    wmem_map_foreach(ws_dlg->map_, dist_map_collect, &entries);
    std::sort(entries.begin(), entries.end(),
              [](const DrawEntry &a, const DrawEntry &b) { return a.count > b.count; });

    /* 2. rebuild the tree: 1 column per variable, then Count and Percent */
    const bool sorting = tree->isSortingEnabled();
    tree->setSortingEnabled(false);
    tree->clear();

    QStringList headers;
    QList<int> types;
    for (const Variable &v : ws_dlg->variables_) { headers << v.name; types << v.type; }
    headers << QObject::tr("Count") << QObject::tr("Percent");

    const int column_count = static_cast<int>(headers.size());
    tree->setColumnCount(column_count);
    tree->setHeaderLabels(headers);

    const qsizetype shown = qMin<qsizetype>(entries.size(), dist_max_rows);
    for (qsizetype r = 0; r < shown; r++) {
        const dist_key_t *k = entries[r].key;
        QStringList modalities;
        for (guint i = 0; i < k->n; i++)                 // noms des membres : à aligner sur ta structure
            modalities << QString::fromUtf8(k->modalities[i]);

        DistributionStatTreeWidgetItem *item =
            new DistributionStatTreeWidgetItem(tree, modalities, types);
        item->update(entries[r].count);
        item->updatePercentage(ws_dlg->packet_count_);
    }

    tree->setSortingEnabled(sorting);
    tree->sortByColumn(column_count - 2, Qt::DescendingOrder);   // tri initial sur Count

    /* 3. entropy (normalized Shannon) of the joint distribution, over ALL entries, not only displayed ones */
    if (entries.size() > 1) {                            // avec 0 ou 1 symbole, la normalisation divise par 0
        QList<int> freq;
        freq.reserve(entries.size());
        int total = 0;
        for (const DrawEntry &e : entries) {
            freq << (int) e.count;
            total += (int) e.count;
        }
        double h = normalized_shannon(freq.data(), static_cast<int>(freq.size()), total);
        ws_dlg->setHint(QString("Entropy (Normalized Shannon): " + QString::number(h)));
    } else {
        ws_dlg->setHint(QString());
    }
}

const QString DistributionDialog::filterExpression()
{
    QString filter_expr;
    if (statsTreeWidget()->selectedItems().count() > 0) {
        QTreeWidgetItem *ti = statsTreeWidget()->selectedItems()[0];

        DistributionStatTreeWidgetItem *fvd_ti = static_cast<DistributionStatTreeWidgetItem *>(ti);
QStringList names;
QList<bool> quotes;
for (const Variable &v : variables_) {
    names  << v.name;
    quotes << (v.type == AGG_FT_STRING);     // guillemets pour les chaînes seulement
}
filter_expr = fvd_ti->filterExpression(names, quotes);

        //filter_expr = fvd_ti->filterExpression(displayFilter_, needsQuotes_);
    }
    return filter_expr;
}

/* Return true if a text can be split into valid tokens.
 * The tokens are stored and returned in the vars list.
 * The separator is ',' and space like characters are allowed (they're trimmed).
 */
bool DistributionDialog::parseFields(const QString &text,
                                     QList<Variable> &vars) const
{
    vars.clear();

    const QStringList tokens = text.split(',');

    /* voluntarily limiting to some variables only */
    if (tokens.size() > dist_max_variables) {
        return false;
    }

    for (const QString &token : tokens) {
        const QByteArray name = token.trimmed().toUtf8();

        const header_field_info *first = proto_registrar_get_byname(name.constData());
        if (!first || !hfi_supports_distribution(first)) {
            vars.clear();
            return false; /* first non existing field is enough to stop */
        }

        const int type = hfi_supports_distribution(first);
        if (!type) {
            vars.clear();
            return false;
        }

        Variable v;
        v.name = QString::fromUtf8(name);
        v.type = type;

        /* Rewind (shouldn't be necessary but let's avoid unexpected-hard-to-debug situations.) */
        while (first->same_name_prev_id != -1) {
            first = proto_registrar_get_nth(first->same_name_prev_id);
        }

        /* Identify all homonyms, if one of them isn't compatible we are not keeping any.
         * XXX - There are not so many of them in the wild,
         * tcp.options.mptcp.reserved.flag is one of them, for example.
         */
        for (const header_field_info *h = first; h; h = h->same_name_next) {

            /* Check the homonym type */
            /* XXX - maybe should we just try to not keep this homonym but still go on checking the others */
            if (hfi_supports_distribution(h) != type) {
                vars.clear();
                return false;
            }

            /* OK, keep it */
            v.hf_indices.append(h->id);

            /* XXX - maybe should we also keep an indication when there are homonyms,
             * as a user feedback ? that might help understand the situation */
        }

        vars.append(v);
    }
    return !vars.isEmpty();
}

/*
 * Checks the given text and returns a validity value.
 * The 'pending' objects are managed here, in order to keep track and
 * store what is entered by the user before really applying later.
 */
SyntaxLineEdit::SyntaxState DistributionDialog::checkInput(const QString &text)
{
    pending_variables_.clear();
    pending_text_.clear();

    if (text.trimmed().isEmpty()) return SyntaxLineEdit::Empty;

    if (!parseFields(text, pending_variables_)) {
        pending_variables_.clear();
        return SyntaxLineEdit::Invalid;
    }
    pending_text_ = text;

    return SyntaxLineEdit::Valid;
}

void DistributionDialog::fillTree()
{

    if (retap_running_) return;

    // filter hasn't changed
    if (!pending_variables_.isEmpty() && pending_text_ == displayFilter_) {
        variables_ = pending_variables_;
    }
    else {
        // Take the user input or the default
        const QString text = displayFilter_.isEmpty() ? QStringLiteral("tcp.completeness.str")
                                                      : displayFilter_;

        // if not valid, go back and wait for a better filter
        if (!parseFields(text, variables_))
            return;
    }

    // build the tap filter, from the variables names and apply the && operator between them
    QStringList names;
    for (const Variable &v : variables_) names << v.name;
    const QByteArray tap_filter = names.join(" && ").toUtf8();

    GString *errorString = set_tap_dfilter(this, tap_filter.constData());

    /* Names were checked before and we believe the filter was built correctly,
     * however we still ensure the tap filter didn't bring any error.
     * XXX - maybe notify the user
     */
    if (errorString) {
        g_string_free(errorString, TRUE);
        return;
    }

    retap_running_ = true;
    statsTreeWidget()->setSortingEnabled(false);
    cap_file_.retapPackets();
    tapDraw(this);
    statsTreeWidget()->setSortingEnabled(true);
    retap_running_ = false;
}

void DistributionDialog::captureFileClosing()
{
    remove_tap_listener(this);

    WiresharkDialog::captureFileClosing();
}

// Store filter from signal.
void DistributionDialog::filterUpdated(QString filter)
{
    /* don't overwrite the default value when starting */
    if(!filter.isEmpty()) {
        displayFilter_ = filter;
    }
}

// This is how an item is represented for exporting.
QList<QVariant> DistributionDialog::treeItemData(QTreeWidgetItem *it) const
{
    // Cast up to our type.
    DistributionStatTreeWidgetItem *nit = dynamic_cast<DistributionStatTreeWidgetItem *>(it);
    if (nit) {
        return nit->rowData();
    }

    return QList<QVariant>();
}

static bool
distribution_statistics_init(const char *args, void*) {
    QStringList args_l = QString(args).split(',');
    QByteArray filter;
    if (args_l.length() > 2) {
        filter = QStringList(args_l.mid(2)).join(",").toUtf8();
    }
    mainApp->emitStatCommandSignal("Distribution", filter.constData(), NULL);
    return true;
}

static stat_tap_ui distribution_statistics_ui = {
    REGISTER_PACKET_ANALYZE_GROUP_UNSORTED,
    NULL,
    "distribution,stat",
    distribution_statistics_init,
    0,
    NULL
};

extern "C" {

void register_tap_listener_qt_distribution_statistics(void);

void
register_tap_listener_qt_distribution_statistics(void)
{
    register_stat_tap_ui(&distribution_statistics_ui, NULL);
}

}
