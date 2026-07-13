# frozen_string_literal: true
#
# Block-form instance_eval / class_eval: statically-authored
# metaprogramming DSL with no injection surface.  Mirrors diaspora
# lib/diaspora/fields/*.rb and lib/diaspora/taggable.rb mixins, where a
# module's `self.included(model)` hook reopens the including class via a
# `do … end` block.  The evaluated code is present in the source and
# cannot be steered by an attacker, so it must NOT fire
# rb.code_exec.class_eval / rb.code_exec.instance_eval.
module Taggable
  def self.included(model)
    model.class_eval do
      has_many :taggings, as: :taggable
      validate :tag_name_max_length, on: :create
    end
  end
end

module Authorable
  def self.included(model)
    model.instance_eval do
      belongs_to :author, class_name: "Person"
    end
  end
end
