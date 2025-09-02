const mongoose = require("mongoose");

const TagSchema = new mongoose.Schema({
  x: Number,
  y: Number,
  menuItem: { type: mongoose.Schema.Types.ObjectId, ref: "MenuItems" },
  label: String,
});

const TaggedImageSchema = new mongoose.Schema({
  imageUrl: String,
  tags: [TagSchema],
});

module.exports = mongoose.model("TaggedImage", TaggedImageSchema);
