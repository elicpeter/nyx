use std::path::PathBuf;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Framework {
    Express,
    Koa,
    Fastify,
    Gin,
    Echo,
    Flask,
    Django,
    Spring,
    Rails,
    Sinatra,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HttpMethod {
    Get,
    Post,
    Put,
    Delete,
    Patch,
    All,
    Use,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AnalysisUnitKind {
    RouteHandler,
    Function,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthCheckKind {
    LoginGuard,
    AdminGuard,
    Ownership,
    Membership,
    TokenExpiry,
    TokenRecipient,
    Other,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OperationKind {
    Read,
    Mutation,
    TokenLookup,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValueSourceKind {
    RequestParam,
    RequestBody,
    RequestQuery,
    Session,
    Identifier,
    MemberField,
    TokenField,
    ArrayIndex,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValueRef {
    pub source_kind: ValueSourceKind,
    pub name: String,
    pub base: Option<String>,
    pub field: Option<String>,
    pub index: Option<String>,
    pub span: (usize, usize),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CallSite {
    pub name: String,
    pub args: Vec<String>,
    pub span: (usize, usize),
}

#[derive(Debug, Clone)]
pub struct AuthCheck {
    pub kind: AuthCheckKind,
    pub callee: String,
    pub subjects: Vec<ValueRef>,
    pub span: (usize, usize),
    pub line: usize,
    pub args: Vec<String>,
    pub condition_text: Option<String>,
}

#[derive(Debug, Clone)]
pub struct SensitiveOperation {
    pub kind: OperationKind,
    pub callee: String,
    pub subjects: Vec<ValueRef>,
    pub span: (usize, usize),
    pub line: usize,
    pub text: String,
}

#[derive(Debug, Clone)]
pub struct AnalysisUnit {
    pub kind: AnalysisUnitKind,
    pub name: Option<String>,
    pub span: (usize, usize),
    pub params: Vec<String>,
    pub context_inputs: Vec<ValueRef>,
    pub call_sites: Vec<CallSite>,
    pub auth_checks: Vec<AuthCheck>,
    pub operations: Vec<SensitiveOperation>,
    pub value_refs: Vec<ValueRef>,
    pub condition_texts: Vec<String>,
    pub line: usize,
}

#[derive(Debug, Clone)]
pub struct RouteRegistration {
    pub framework: Framework,
    pub method: HttpMethod,
    pub path: String,
    pub middleware: Vec<String>,
    pub handler_span: (usize, usize),
    pub handler_params: Vec<String>,
    pub file: PathBuf,
    pub line: usize,
    pub unit_idx: usize,
    pub middleware_calls: Vec<CallSite>,
}

#[derive(Debug, Clone, Default)]
pub struct AuthorizationModel {
    pub routes: Vec<RouteRegistration>,
    pub units: Vec<AnalysisUnit>,
}

impl AuthorizationModel {
    pub fn extend(&mut self, other: AuthorizationModel) {
        let unit_offset = self.units.len();
        self.units.extend(other.units);
        self.routes
            .extend(other.routes.into_iter().map(|mut route| {
                route.unit_idx += unit_offset;
                route
            }));
    }
}
